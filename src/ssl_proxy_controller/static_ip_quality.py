"""Static IP speed test + quality report.

Companion to ``static_ips.py``. Where ``static_ips.py`` answers
"is this IP:port reachable?", this module answers two harder questions:

* **Speed test** — what's the actual operator-visible performance of a
  proxy IP? Composed of:
    1. TCP latency over N samples → median, jitter (stddev), loss%
    2. Application-layer RTT — fetch a tiny endpoint via the proxy
    3. Download bandwidth — pull a known-size payload via the proxy
    4. Upload bandwidth — POST a known-size payload via the proxy

  Bandwidth + app-layer RTT only run for protocols that can carry
  real traffic (socks5 / socks4 / http / https). For pure tcp/udp/ssh
  rows we just return latency stats.

* **Quality report** — risk + classification using only KEYLESS,
  no-account-required sources. Earlier revisions called proxycheck.io,
  AbuseIPDB, and IPQualityScore; those were removed because every
  useful field they exposed required a paid plan or rate-limited
  free-tier key. The current source list is deliberately small but
  100% free-of-charge and free-of-signup:
    - ip-api.com (free, no key) — geo, ASN, ISP, org, mobile / proxy /
      hosting flags. We use the bitmask field selector to get
      paid-tier flags on the free tier.
    - RDAP (rdap.org public mirror) — registry country vs geo country
      to flag re-announced IPs.
    - Spamhaus DNSBL (DNS query) — listing in zen.spamhaus.org.
    - Scamalytics (public HTML scrape) — fraud score + risk tier.
    - Streaming unlock — extended set (15+ services) probed from the
      admin host (vantage point).

The whole module is dependency-light. PySocks is the only non-stdlib
import and it's gracefully degraded — if it's missing, the bandwidth
test for SOCKS5 protocols is skipped with a clear "PySocks not
installed" reason rather than crashing.
"""
from __future__ import annotations

import base64
import json
import logging
import socket
import ssl as _ssl
import statistics
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Any

LOGGER = logging.getLogger("ssl_proxy_controller.static_ip_quality")


# ---------------------------------------------------------------------------
# Speed test
# ---------------------------------------------------------------------------

# Where we pull/push bytes for the bandwidth test. Cloudflare's
# speed.cloudflare.com API gives well-defined byte-sized endpoints
# that don't rate-limit and respond fast. Falling back to httpbin and
# httpbingo when CF is unreachable through a given proxy.
# Bandwidth measurement endpoints. We request a generous chunk (32 MiB)
# but stream-read so we can stop early once ``_BANDWIDTH_TARGET_SECONDS``
# elapses — that gives accurate steady-state Mbps without needing the
# whole transfer to complete on a slow proxy.
_BANDWIDTH_TARGET_BYTES = 32 * 1024 * 1024  # 32 MiB cap
_BANDWIDTH_TARGET_SECONDS = 8.0             # ramp-out window
_BANDWIDTH_MIN_BYTES_FOR_VALID = 256 * 1024  # below this we report "(too short)"

_DOWNLOAD_URLS = [
  # speed.cloudflare.com is the gold standard — globally CDN'd, no
  # rate limit, returns exactly the bytes we ask for. The bytes=
  # query param is honored up to its server-side cap. We oversize
  # the request and stop reading at our target.
  "https://speed.cloudflare.com/__down?bytes=33554432",
  "https://httpbingo.org/bytes/33554432",
  "https://www.google.com/generate_204",  # last-resort 0-byte reachability check
]

_UPLOAD_URLS = [
  "https://speed.cloudflare.com/__up",
  "https://httpbingo.org/post",
]

# App-layer RTT — try multiple endpoints because residential proxies
# block surprising things. The first reachable wins.
_APP_RTT_URLS = [
  "https://www.cloudflare.com/cdn-cgi/trace",
  "https://1.1.1.1/cdn-cgi/trace",
  "https://www.google.com/generate_204",
]
_APP_RTT_URL = _APP_RTT_URLS[0]  # legacy single-URL pointer
_BANDWIDTH_BYTES = 1 << 20  # 1 MiB
_BANDWIDTH_TIMEOUT = 30.0


def _tcp_latency_samples(ip: str, port: int, *, samples: int = 8, timeout: float = 3.0) -> dict[str, Any]:
  """N TCP three-way handshakes; return latency stats.

  Most accurate quick metric we can collect without sending payload —
  also doubles as a packet-loss proxy: failed connect == lost.
  """
  if not port:
    return {"samples": 0, "ok": 0, "loss_pct": None, "p50_ms": None,
            "p90_ms": None, "min_ms": None, "max_ms": None,
            "jitter_ms": None, "error": "no port to dial"}
  results: list[float] = []
  errors: list[str] = []
  for _ in range(max(1, samples)):
    t0 = time.monotonic()
    try:
      with socket.create_connection((ip, port), timeout=timeout):
        results.append((time.monotonic() - t0) * 1000.0)
    except Exception as exc:  # noqa: BLE001
      errors.append(str(exc)[:120])
  ok = len(results)
  total = max(1, samples)
  loss_pct = round((1 - ok / total) * 100, 1)
  if not results:
    return {
      "samples": total, "ok": 0, "loss_pct": loss_pct,
      "p50_ms": None, "p90_ms": None, "min_ms": None, "max_ms": None,
      "jitter_ms": None, "error": errors[0] if errors else "all samples failed",
    }
  results_sorted = sorted(results)
  p50 = results_sorted[len(results_sorted) // 2]
  p90 = results_sorted[min(len(results_sorted) - 1, int(len(results_sorted) * 0.9))]
  jitter = statistics.pstdev(results) if len(results) > 1 else 0.0
  return {
    "samples": total,
    "ok": ok,
    "loss_pct": loss_pct,
    "p50_ms": round(p50, 2),
    "p90_ms": round(p90, 2),
    "min_ms": round(min(results), 2),
    "max_ms": round(max(results), 2),
    "jitter_ms": round(jitter, 2),
    "error": None if ok == total else f"{total - ok}/{total} failed",
  }


def _build_proxy_opener(protocol: str, host: str, port: int,
                        username: str | None, password: str | None):
  """Return a urllib opener that routes traffic through the given
  proxy. ``None`` if the protocol isn't a proxy we can use for
  bandwidth tests (tcp / udp / ssh / shadowsocks / trojan / vless /
  vmess / wireguard etc.)."""
  proto = (protocol or "").lower()

  # HTTP / HTTPS proxies: stdlib ProxyHandler is fine. CONNECT method
  # is built-in on urllib for https targets through an http proxy.
  if proto in ("http", "https"):
    cred = ""
    if username or password:
      cred = (urllib.parse.quote(username or "", safe="") + ":" +
              urllib.parse.quote(password or "", safe="") + "@")
    proxy_url = f"{proto}://{cred}{host}:{port}"
    handler = urllib.request.ProxyHandler({
      "http": proxy_url, "https": proxy_url,
    })
    # Build the opener WITHOUT inheriting system proxy env vars
    # (HTTP_PROXY / HTTPS_PROXY / etc.). Otherwise urllib's
    # ProxyHandler resolution wins, every request gets re-rewritten
    # to the system proxy first, and we end up tunneling
    # ``system-proxy:port`` (e.g. 172.16.10.254:7890 from Clash) as
    # the destination through OUR proxy — which gets refused as a
    # bogus private address.
    return urllib.request.build_opener(
      urllib.request.HTTPHandler(),
      urllib.request.HTTPSHandler(),
      handler,
    )

  # SOCKS5 — minimal inline implementation of RFC 1928 + RFC 1929
  # (username/password sub-negotiation). We only need CONNECT, so the
  # full ~300 lines of PySocks is overkill. The factory returns a
  # plain socket already authenticated and tunneled to the destination.
  if proto == "socks5":
    sock_factory = lambda host_dst, port_dst: _connect_socks5(  # noqa: E731
      host, port, host_dst, port_dst, username, password,
    )

    class _Socks5HTTPConnection(_HTTPConnectionMixin):  # noqa: N801
      _factory_addr = staticmethod(sock_factory)

    class _Socks5HTTPSConnection(_HTTPSConnectionMixin):  # noqa: N801
      _factory_addr = staticmethod(sock_factory)

    class _Socks5HTTPHandler(urllib.request.HTTPHandler):  # noqa: N801
      def http_open(self, req):
        return self.do_open(_Socks5HTTPConnection, req)

    class _Socks5HTTPSHandler(urllib.request.HTTPSHandler):  # noqa: N801
      def https_open(self, req):
        return self.do_open(_Socks5HTTPSConnection, req)

    # Empty ProxyHandler explicitly *disables* inheritance of system
    # ``HTTP_PROXY`` / ``HTTPS_PROXY`` env vars. Without this,
    # urllib's default ProxyHandler intercepts the request first and
    # rewrites the destination to the system proxy — so the SOCKS5
    # tunnel ends up trying to reach e.g. ``172.16.10.254:7890``
    # (Clash on the operator's Mac) instead of the real target,
    # which the SOCKS5 server refuses as a bogus private address.
    return urllib.request.build_opener(
      urllib.request.ProxyHandler({}),
      _Socks5HTTPHandler(),
      _Socks5HTTPSHandler(),
    )

  # SOCKS4 — rare in residential proxy world; deliberately not
  # implemented here. Operators on socks4 can fall back to TCP-only
  # latency stats for now.
  if proto == "socks4":
    raise RuntimeError("socks4 bandwidth test not yet implemented")

  return None


# ---- Inline minimal SOCKS5 client (RFC 1928 + RFC 1929) -------------


def _connect_socks5(proxy_host: str, proxy_port: int,
                    dest_host: str, dest_port: int,
                    username: str | None, password: str | None,
                    *, timeout: float = _BANDWIDTH_TIMEOUT) -> socket.socket:
  """Open a TCP socket through a SOCKS5 proxy. Returns the socket
  already tunneled to ``dest_host:dest_port`` so the caller can
  treat it as a normal connection. Implements just the CONNECT
  command + optional username/password auth — enough for HTTP/HTTPS
  bandwidth probes."""
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.settimeout(timeout)
  s.connect((proxy_host, proxy_port))
  try:
    # ---- Greeting ----
    methods = b"\x00\x02" if (username or password) else b"\x00"
    s.sendall(b"\x05" + bytes([len(methods)]) + methods)
    ver, method = _recv_exact(s, 2)
    if ver != 0x05:
      raise OSError(f"bad SOCKS5 greeting reply ver={ver}")
    if method == 0xFF:
      raise OSError("SOCKS5 server rejected all auth methods")
    # ---- Username/password auth (RFC 1929) ----
    if method == 0x02:
      u = (username or "").encode("utf-8")
      p = (password or "").encode("utf-8")
      if len(u) > 255 or len(p) > 255:
        raise OSError("SOCKS5 user/pass exceed 255 bytes")
      s.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
      av, status = _recv_exact(s, 2)
      if av != 0x01 or status != 0x00:
        raise OSError(f"SOCKS5 auth failed status={status}")
    elif method != 0x00:
      raise OSError(f"SOCKS5 server picked unsupported method {method}")
    # ---- Connect request ----
    # ATYP: prefer ipv4 numeric, otherwise domain-name.
    try:
      packed = socket.inet_aton(dest_host)
      addr_block = b"\x01" + packed
    except OSError:
      h = dest_host.encode("idna") if any(ord(c) > 127 for c in dest_host) \
          else dest_host.encode("ascii")
      if len(h) > 255:
        raise OSError("dest host too long for SOCKS5 ATYP=03")
      addr_block = b"\x03" + bytes([len(h)]) + h
    port_block = dest_port.to_bytes(2, "big")
    s.sendall(b"\x05\x01\x00" + addr_block + port_block)
    # Reply: VER REP RSV ATYP BND.ADDR BND.PORT
    rver, rep, _rsv, ratyp = _recv_exact(s, 4)
    if rver != 0x05:
      raise OSError(f"bad SOCKS5 connect-reply ver={rver}")
    if rep != 0x00:
      raise OSError(f"SOCKS5 connect refused (rep={rep})")
    # Drain the bound-address fields (we don't need them).
    if ratyp == 0x01:
      _recv_exact(s, 4 + 2)
    elif ratyp == 0x03:
      ln = _recv_exact(s, 1)[0]
      _recv_exact(s, ln + 2)
    elif ratyp == 0x04:
      _recv_exact(s, 16 + 2)
    else:
      raise OSError(f"SOCKS5 reply unknown ATYP={ratyp}")
    return s
  except Exception:
    try: s.close()
    except Exception: pass
    raise


def _recv_exact(s: socket.socket, n: int) -> bytes:
  buf = bytearray()
  while len(buf) < n:
    chunk = s.recv(n - len(buf))
    if not chunk:
      raise OSError(f"SOCKS5 short read (got {len(buf)} of {n})")
    buf.extend(chunk)
  return bytes(buf)


# Replacement HTTP/HTTPS connection classes that use a PySocks-wrapped
# socket as their transport. The minimal surface area we need is
# ``self.sock = factory()`` before the request body is sent.
import http.client as _http_client


class _HTTPConnectionMixin(_http_client.HTTPConnection):  # noqa: N801
  # Subclasses set ``_factory_addr(host, port) -> already-connected
  # socket`` to tunnel through whatever proxy. The HTTP transport
  # then uses that socket as if it were a direct connection.
  _factory_addr = None  # type: ignore[assignment]
  def connect(self):
    sock = self._factory_addr(self.host, self.port)  # type: ignore[misc]
    sock.settimeout(self.timeout if self.timeout is not None else _BANDWIDTH_TIMEOUT)
    self.sock = sock


class _HTTPSConnectionMixin(_http_client.HTTPSConnection):  # noqa: N801
  _factory_addr = None  # type: ignore[assignment]
  def connect(self):
    sock = self._factory_addr(self.host, self.port)  # type: ignore[misc]
    sock.settimeout(self.timeout if self.timeout is not None else _BANDWIDTH_TIMEOUT)
    ctx = self._context if self._context else _ssl.create_default_context()
    self.sock = ctx.wrap_socket(sock, server_hostname=self.host)


_USER_AGENT = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) "
               "AppleWebKit/537.36 (KHTML, like Gecko) "
               "Chrome/123.0.0.0 Safari/537.36")


def _bandwidth_test_via_proxy(opener, *, direction: str = "down") -> dict[str, Any]:
  """Time-bounded bandwidth probe through the given urllib opener.

  Strategy: stream up to ``_BANDWIDTH_TARGET_BYTES`` (32 MiB) but
  stop reading / writing once ``_BANDWIDTH_TARGET_SECONDS`` (8 s)
  elapsed. This avoids two failure modes the older implementation
  had:

  1. **Too-small window** — the previous 1 MiB transfer was so brief
     that TCP slow-start dominated, and we reported numbers ~10×
     below the proxy's actual capacity. With an 8 s window, slow-
     start is amortized.
  2. **Tail latency on slow proxies** — fixed-size 25 MiB on a 1
     Mbps proxy would take 200 s, blowing the modal timeout. Time-
     bounding caps wall time at ``_BANDWIDTH_TARGET_SECONDS + a bit``.

  Returns ``{bytes, seconds, mbps, url, error}``. ``mbps`` is None
  when the transfer was too short to be meaningful.
  """
  urls = _DOWNLOAD_URLS if direction == "down" else _UPLOAD_URLS
  last_error: str | None = None
  for url in urls:
    try:
      if direction == "down":
        req = urllib.request.Request(url, method="GET",
                                     headers={"User-Agent": _USER_AGENT})
        t0 = time.monotonic()
        with opener.open(req, timeout=_BANDWIDTH_TIMEOUT) as resp:
          received = 0
          while received < _BANDWIDTH_TARGET_BYTES:
            chunk = resp.read(128 * 1024)
            if not chunk:
              break
            received += len(chunk)
            if (time.monotonic() - t0) >= _BANDWIDTH_TARGET_SECONDS:
              break
        bytes_count = received
      else:
        # Stream-write: start with a 4 MiB chunk and keep posting
        # until we hit the time/byte budget. urllib doesn't easily
        # support chunked uploads, so we send one POST sized to
        # whatever fits the budget — for an 8s window at typical
        # residential upload speeds (5-20 Mbps) that's 5-20 MiB.
        # To keep things simple and bounded, we pick an aggressive
        # 16 MiB upload payload; anything faster than 16 Mbps
        # finishes before timeout, slower hits timeout.
        payload_size = min(_BANDWIDTH_TARGET_BYTES, 16 * 1024 * 1024)
        payload = b"x" * payload_size
        req = urllib.request.Request(
          url, data=payload, method="POST",
          headers={"Content-Type": "application/octet-stream",
                   "User-Agent": _USER_AGENT},
        )
        t0 = time.monotonic()
        with opener.open(req, timeout=_BANDWIDTH_TIMEOUT) as resp:
          resp.read(8 * 1024)
        bytes_count = len(payload)
      seconds = max(time.monotonic() - t0, 0.001)
      mbps = (bytes_count * 8) / seconds / 1_000_000
      # Reject implausibly tiny transfers (≤ 256 KiB) — the throughput
      # estimate would be dominated by slow-start and DNS. Surface it
      # as a soft error so the operator knows the result isn't
      # trustworthy.
      if bytes_count < _BANDWIDTH_MIN_BYTES_FOR_VALID:
        return {
          "bytes": bytes_count, "seconds": round(seconds, 3),
          "mbps": None, "url": url,
          "error": f"transfer too small ({bytes_count} bytes) — endpoint may have rate-capped",
        }
      return {
        "bytes": bytes_count, "seconds": round(seconds, 3),
        "mbps": round(mbps, 2), "url": url, "error": None,
      }
    except Exception as exc:  # noqa: BLE001
      last_error = f"{type(exc).__name__}: {str(exc)[:160]}"
      continue
  return {
    "bytes": 0, "seconds": None, "mbps": None,
    "url": None, "error": last_error or "all endpoints failed",
  }


def _app_rtt_via_proxy(opener) -> dict[str, Any]:
  """Application-layer RTT — measured by GETting a tiny well-known
  endpoint through the proxy. Reflects more than just TCP — TLS
  handshake, HTTP request/response, server-side processing all
  contribute. Tries multiple destinations because residential/ISP
  proxies often arbitrarily allow-list a subset of public hosts."""
  last_error: str | None = None
  _UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) "
         "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36")
  for url in _APP_RTT_URLS:
    try:
      t0 = time.monotonic()
      req = urllib.request.Request(url, method="GET", headers={"User-Agent": _UA})
      with opener.open(req, timeout=_BANDWIDTH_TIMEOUT) as resp:
        body = resp.read(4096)
      elapsed = round((time.monotonic() - t0) * 1000.0, 2)
      visible_ip = None
      try:
        for line in body.decode("utf-8", errors="replace").splitlines():
          if line.startswith("ip="):
            visible_ip = line.split("=", 1)[1].strip()
            break
      except Exception:
        pass
      return {"rtt_ms": elapsed, "visible_ip": visible_ip, "error": None, "url": url}
    except Exception as exc:  # noqa: BLE001
      last_error = f"{type(exc).__name__}: {str(exc)[:160]}"
      continue
  return {"rtt_ms": None, "visible_ip": None, "url": None,
          "error": last_error or "all endpoints failed"}


def run_speed_test(rec, *,
                   include_latency: bool = True,
                   include_bandwidth: bool = True,
                   include_app_rtt: bool = True) -> dict[str, Any]:
  """Run the speed-test sequence on one StaticIpRecord.

  Each component can be opted-in or out — the unified Test modal
  uses this to let operators run latency-only without paying the 30s
  bandwidth probe cost.

  Always returns the full dict shape; skipped components stay ``None``.
  """
  out: dict[str, Any] = {
    "ip": rec.ip, "port": rec.port, "protocol": rec.protocol,
    "started_at": time.time(),
    "latency": _tcp_latency_samples(rec.ip, rec.port or 0) if include_latency else None,
    "bandwidth_down": None,
    "bandwidth_up": None,
    "app_rtt": None,
    "notes": [],
    "ran": {
      "latency": include_latency,
      "bandwidth": include_bandwidth,
      "app_rtt": include_app_rtt,
    },
  }
  proto = (rec.protocol or "").lower()
  needs_proxy = include_bandwidth or include_app_rtt
  if needs_proxy and proto in ("http", "https", "socks5", "socks4") and rec.port:
    try:
      opener = _build_proxy_opener(proto, rec.ip, rec.port, rec.username, rec.password)
    except Exception as exc:  # noqa: BLE001
      out["notes"].append(f"proxy opener unavailable: {exc}")
      opener = None
    if opener is not None:
      # Sequential, NOT parallel — see history note: parallel through
      # one proxy connection divided bandwidth ~3 ways.
      if include_app_rtt:
        out["app_rtt"] = _app_rtt_via_proxy(opener)
      if include_bandwidth:
        out["bandwidth_down"] = _bandwidth_test_via_proxy(opener, direction="down")
        out["bandwidth_up"] = _bandwidth_test_via_proxy(opener, direction="up")
  elif needs_proxy:
    out["notes"].append(
      f"protocol {rec.protocol!r} can't carry HTTP traffic — bandwidth/app-RTT skipped"
    )
  out["finished_at"] = time.time()
  out["wall_time_seconds"] = round(out["finished_at"] - out["started_at"], 2)
  # Roll up a single "ok" boolean — only counts components that were
  # asked to run. Latency's ``ok`` flag is the gate; bandwidth must
  # succeed if requested; missing components don't count against ok.
  ok = True
  if include_latency:
    ok = ok and bool(out["latency"] and out["latency"].get("ok"))
  if include_bandwidth and proto in ("http", "https", "socks5", "socks4"):
    bw_ok = (out["bandwidth_down"] and out["bandwidth_down"].get("mbps") is not None) \
         or (out["bandwidth_up"] and out["bandwidth_up"].get("mbps") is not None)
    ok = ok and bool(bw_ok)
  out["ok"] = ok
  return out


# ---------------------------------------------------------------------------
# Quality report
# ---------------------------------------------------------------------------

_SCAMALYTICS_URL = "https://scamalytics.com/ip/{ip}"

# Spamhaus DNSBL zones — listing in any indicates the IP is on
# Spamhaus's blocklist (SBL/XBL/PBL combined as ZEN). DNS-based
# protocol: query ``<reversed-ip>.zen.spamhaus.org``; if it resolves
# to a 127.0.0.X address, IP is listed. Anything else (NXDOMAIN /
# 198.18.0.x "your resolver is too public" / network error) means
# we can't tell — report ``available=False`` with the reason.
_SPAMHAUS_ZONES = ("zen.spamhaus.org",)


def _http_get_json(url: str, *, headers: dict[str, str] | None = None,
                   timeout: float = 6.0) -> dict[str, Any]:
  req = urllib.request.Request(url, headers=headers or {})
  with urllib.request.urlopen(req, timeout=timeout) as resp:
    return json.loads(resp.read().decode("utf-8"))


def _quality_spamhaus(ip: str, *, timeout: float = 4.0) -> dict[str, Any]:
  """Spamhaus DNSBL check — pure DNS, no key, no rate-limit (when
  queried via the operator's local resolver). Returns
  ``{listed, zones, available, error}``.

  Mechanics: reverse the IP octets, append the zone, and look up the
  A record. A 127.0.0.X response means listed; NXDOMAIN means clean.
  Special 198.18.0.X responses mean "your resolver is too public" —
  Spamhaus blocks queries from Google DNS / Cloudflare DNS as a ToS
  enforcement. We surface that case as ``available=False`` so the
  operator knows to either change DNS or skip this source.
  """
  if not ip or ":" in ip:  # IPv6 needs different reversed form; skip for now
    return {"available": False, "listed": False, "error": "IPv6 not supported"}
  parts = ip.split(".")
  if len(parts) != 4:
    return {"available": False, "listed": False, "error": "invalid IPv4"}
  reversed_ip = ".".join(reversed(parts))
  hits: list[dict[str, str]] = []
  unreachable = 0
  for zone in _SPAMHAUS_ZONES:
    host = f"{reversed_ip}.{zone}"
    try:
      old_to = socket.getdefaulttimeout()
      socket.setdefaulttimeout(timeout)
      try:
        addr = socket.gethostbyname(host)
      finally:
        socket.setdefaulttimeout(old_to)
      if addr.startswith("127.0.0."):
        # 127.0.0.{2,3,...} — different bits == different sub-lists.
        # We just record the raw response code; UI can interpret.
        hits.append({"zone": zone, "code": addr})
      elif addr.startswith("198.18."):
        # Spamhaus's "your DNS resolver is open / public" rejection.
        # Result is unusable from public DNS like 8.8.8.8 / 1.1.1.1;
        # only meaningful when admin host uses a private/ISP DNS.
        unreachable += 1
    except socket.gaierror:
      pass  # NXDOMAIN — clean for this zone
    except Exception:
      unreachable += 1
  if unreachable == len(_SPAMHAUS_ZONES) and not hits:
    return {
      "available": False, "listed": False,
      "error": "DNS resolver is too public — Spamhaus rejected the query",
    }
  return {
    "available": True,
    "listed": bool(hits),
    "hits": hits,
    "error": None,
  }


def _quality_scamalytics(ip: str, *, timeout: float = 8.0) -> dict[str, Any]:
  """Scamalytics public lookup — scrape the HTML report page.

  Their open free tier serves a static page per IP at
  ``scamalytics.com/ip/{ip}``. Fields we extract:

  * ``score``      — fraud risk 0-100 (lower is better)
  * ``risk``       — categorical: ``very low / low / medium / high / very high``
  * ``isp``        — ISP / org name
  * ``country``    — geo country
  * ``proxy``      — boolean (in their HTML, "Anonymizing VPN: Yes/No")

  Falls back to ``available=False`` when Cloudflare's anti-bot page
  is returned instead — happens occasionally from cloud sandboxes
  but rarely from a real residential admin host.
  """
  # ``safe=":"`` keeps IPv6 colons literal — without this Scamalytics
  # gets ``2001%3Adb8%3A%3A1`` which 404s on their site.
  url = _SCAMALYTICS_URL.format(ip=urllib.parse.quote(ip, safe=":"))
  try:
    req = urllib.request.Request(url, headers={
      "User-Agent": _USER_AGENT,
      "Accept-Language": "en-US,en;q=0.9",
    })
    with urllib.request.urlopen(req, timeout=timeout) as resp:
      html = resp.read(120 * 1024).decode("utf-8", errors="replace")
  except Exception as exc:  # noqa: BLE001
    return {"available": False, "error": f"{type(exc).__name__}: {str(exc)[:160]}"}
  if "Just a moment" in html or "cf-error-details" in html or "Please enable cookies" in html:
    return {"available": False, "error": "Cloudflare anti-bot challenge"}
  import re as _re
  out: dict[str, Any] = {"available": True, "raw_url": url}
  m = _re.search(r'<div[^>]*id="risk_color"[^>]*>\s*Fraud Score:\s*(\d+)\s*</div>', html, _re.I)
  if not m:
    m = _re.search(r'(?:Fraud\s*Score|Risk\s*Score)[^0-9]*(\d{1,3})', html, _re.I)
  if m:
    try: out["score"] = int(m.group(1))
    except Exception: pass
  m = _re.search(r'<div[^>]*class="[^"]*panel_(very low|low|medium|high|very high)[^"]*"', html, _re.I)
  if m:
    out["risk"] = m.group(1).lower()
  else:
    m = _re.search(r'(?:Risk:?)\s*(<[^>]*>)*\s*(very low|low|medium|high|very high)', html, _re.I)
    if m:
      out["risk"] = m.group(2).lower()
  m = _re.search(r'<th[^>]*>\s*ISP Name\s*</th>\s*<td[^>]*>(.*?)</td>', html, _re.I | _re.S)
  if m:
    out["isp"] = _re.sub(r"<[^>]+>", "", m.group(1)).strip()
  m = _re.search(r'<th[^>]*>\s*Country (?:Name|Code)\s*</th>\s*<td[^>]*>(.*?)</td>', html, _re.I | _re.S)
  if m:
    out["country"] = _re.sub(r"<[^>]+>", "", m.group(1)).strip()
  for label, key in (("Anonymizing VPN", "is_anonymizing_vpn"),
                     ("Proxy", "is_proxy"),
                     ("Tor Exit Node", "is_tor"),
                     ("Server", "is_server")):
    m = _re.search(rf'<th[^>]*>\s*{label}\s*</th>\s*<td[^>]*>(.*?)</td>', html, _re.I | _re.S)
    if m:
      v = _re.sub(r"<[^>]+>", "", m.group(1)).strip().lower()
      out[key] = (v == "yes" or v == "true")
  return out


def _quality_native(ip: str, geo_basics: dict | None,
                    *, timeout: float = 6.0) -> dict[str, Any]:
  """Compare the IP's RIR-registered country (RDAP) to the country
  the geo APIs detect it being USED in. If they match, the IP is
  routed natively from where it was allocated; if they differ, the
  IP is being announced from a different country (often a sign of
  proxy / hosting reannouncement, or a rented prefix).

  RDAP is the modern free replacement for whois — every RIR (ARIN,
  RIPE, APNIC, AFRINIC, LACNIC) runs an HTTPS RDAP service. We
  redirect-follow from rdap.org which knows which RIR owns the IP.
  """
  if not ip:
    return {"available": False, "error": "no IP"}
  # RDAP supports both IPv4 and IPv6 — rdap.org redirects to the right
  # RIR for either family. Don't skip IPv6 here; the IP just goes into
  # the URL as-is.
  url = f"https://rdap.org/ip/{urllib.parse.quote(ip, safe=':')}"
  try:
    req = urllib.request.Request(url, headers={"Accept": "application/rdap+json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
      data = json.loads(resp.read().decode("utf-8"))
  except Exception as exc:  # noqa: BLE001
    return {"available": False, "error": f"{type(exc).__name__}: {str(exc)[:160]}"}
  # Country extraction: ARIN puts it in vCard entities; RIPE/APNIC have
  # a top-level ``country`` field.
  registered_cc = (data.get("country") or "").strip().upper() or None
  if not registered_cc:
    # Walk entities/vcardArray to find a ``country-name`` line.
    for ent in data.get("entities") or []:
      for arr in ent.get("vcardArray", []):
        if not isinstance(arr, list):
          continue
        for tup in arr:
          if isinstance(tup, list) and len(tup) >= 4 and tup[0] == "adr":
            params = tup[1] if isinstance(tup[1], dict) else {}
            cc = params.get("cc")
            if cc:
              registered_cc = cc.upper(); break
        if registered_cc: break
      if registered_cc: break
  used_cc = (geo_basics or {}).get("country_code")
  used_cc = used_cc.upper() if isinstance(used_cc, str) else None
  same = bool(registered_cc and used_cc and registered_cc == used_cc)
  return {
    "available": True,
    "registered_cc": registered_cc,
    "used_cc": used_cc,
    "native": same,
    "rir": (data.get("port43") or "").lower() or None,
  }


# Streaming unlock — extended set. Each entry is
# (service_name, probe_url, expected_marker, blocked_marker, kind).
# The probes deliberately use HEAD or small GETs so they're cheap and
# don't trigger anti-bot heuristics. Detection logic varies per
# service — some respond with country-specific HTML, others with a
# 403/451, others with a JSON region field.
_STREAM_PROBES = [
  ("Netflix",          "https://www.netflix.com/title/81280792"),       # exclusive title
  ("YouTube Premium",  "https://www.youtube.com/premium"),
  ("ChatGPT",          "https://chat.openai.com/cdn-cgi/trace"),
  ("Disney+",          "https://disneyplus.com/"),
  ("HBO Max",          "https://www.max.com/"),
  ("Hulu",             "https://www.hulu.com/welcome"),
  ("Amazon Prime Video", "https://www.primevideo.com/"),
  ("Apple TV+",        "https://tv.apple.com/"),
  ("Paramount+",       "https://www.paramountplus.com/"),
  ("BBC iPlayer",      "https://www.bbc.co.uk/iplayer"),
  ("DAZN",             "https://www.dazn.com/"),
  ("Spotify",          "https://www.spotify.com/"),
  ("TikTok",           "https://www.tiktok.com/"),
  ("Bilibili",         "https://www.bilibili.com/"),
  ("Crunchyroll",      "https://www.crunchyroll.com/"),
  ("AbemaTV",          "https://abema.tv/"),
]


def _check_stream_one(name: str, url: str, *, timeout: float = 6.0) -> dict[str, Any]:
  """Generic streaming-unlock probe: hit the URL and classify based
  on status code + a few well-known regional markers. Detection is
  best-effort — for many services the only signal is "responds 200
  vs. 403/451"; geo-restriction often shows as a redirect.
  """
  try:
    req = urllib.request.Request(url, method="GET", headers={
      "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0 Safari/537.36",
      "Accept-Language": "en-US,en;q=0.9",
    })
    with urllib.request.urlopen(req, timeout=timeout) as resp:
      code = resp.status
      body = resp.read(4096)
  except urllib.error.HTTPError as exc:
    return _classify_stream(name, exc.code, b"", url, str(exc)[:120])
  except Exception as exc:  # noqa: BLE001
    return {"service": name, "status": "error", "error": str(exc)[:120]}
  return _classify_stream(name, code, body, url, None)


def _classify_stream(name: str, code: int, body: bytes,
                     url: str, err: str | None) -> dict[str, Any]:
  if code in (403, 451):
    return {"service": name, "status": "blocked", "code": code, "error": err}
  if code in (301, 302, 303, 307, 308):
    return {"service": name, "status": "redirect", "code": code, "error": err}
  if 200 <= code < 300:
    txt = body.decode("utf-8", errors="replace").lower() if body else ""
    if "not available in your region" in txt or "geographic restriction" in txt:
      return {"service": name, "status": "blocked", "code": code, "error": err}
    if "page-blocked" in txt or "noaccessible" in txt:
      return {"service": name, "status": "blocked", "code": code, "error": err}
    return {"service": name, "status": "available", "code": code, "error": err}
  return {"service": name, "status": "unknown", "code": code, "error": err}


def _streaming_unlock_extended(*, opener=None, max_workers: int = 8) -> list[dict[str, Any]]:
  """Run all streaming probes in parallel from the admin host (or
  through a given proxy opener — passing one routes the probes via
  the proxy so the operator sees what the proxy can/can't reach)."""
  # Note: the current default still probes from the admin host, not
  # via the proxy. Future work: thread an opener through the urllib
  # call inside _check_stream_one.
  with ThreadPoolExecutor(max_workers=max_workers) as ex:
    return list(ex.map(lambda p: _check_stream_one(p[0], p[1]), _STREAM_PROBES))


def run_quality_report(rec, *, include_streaming: bool = True) -> dict[str, Any]:
  """Aggregate quality lookup across every keyless source.

  Each source is a separate parallel job. Failures are reported per-
  source but never block the others. The shape of the response is
  stable so the UI can render whatever's available.

  Subject IP rules:
    - kind='static' (default) -> queries use ``rec.ip`` directly.
    - kind='gateway' -> queries use ``rec.exit_ip`` when set, else the
      report skips IP-bound lookups and only runs streaming probes
      from the admin host. The gateway hostname's geo is not the
      proxy's apparent jurisdiction, so reporting on it would mislead.

  Sources (all free, no signup, no API keys):
    - ip-api.com (geo + ASN + hosting/proxy/mobile flags)
    - RDAP via rdap.org (registered vs used country → native flag)
    - Spamhaus DNSBL (zen.spamhaus.org)
    - Scamalytics public scrape (fraud score + risk tier)
    - Streaming unlock probes (16 services from admin host)
  """
  # Pick the subject IP — the address whose location/risk we're
  # reporting on, NOT the connection target. They diverge for gateway
  # rows (gateway target = rec.ip, exit IP = rec.exit_ip).
  kind = getattr(rec, "kind", "static") or "static"
  exit_ip = getattr(rec, "exit_ip", None)
  if kind == "gateway":
    subject_ip = exit_ip
  else:
    subject_ip = rec.ip
  out: dict[str, Any] = {
    # Primary key for the response is the subject we actually queried;
    # keeping ``connect_target`` so the UI can show "via gateway X" when
    # the two diverge.
    "ip": subject_ip or rec.ip,
    "connect_target": rec.ip,
    "subject_kind": kind,
    "started_at": time.time(),
    "ip_api": None,
    "spamhaus": None,
    "scamalytics": None,
    "native": None,
    "streaming": [],
  }
  if not subject_ip:
    # Gateway with no extracted exit_ip — we can still measure
    # streaming unlock from the admin host (vantage point), but every
    # IP-bound source is meaningless. Surface a clear "no subject" hint
    # so the UI tells the operator to set exit_ip in Edit.
    out["error"] = "no subject IP — gateway row with no exit_ip"
    if include_streaming:
      out["streaming"] = _streaming_unlock_extended()
    out["finished_at"] = time.time()
    out["wall_time_seconds"] = round(out["finished_at"] - out["started_at"], 2)
    return out
  ip = subject_ip
  # Local import to avoid circular dep: ip-api lookup lives in
  # static_ips.py since it pre-dates this module.
  from . import static_ips as _static_ips

  # Phase 1: ip-api first because the native detection needs to know
  # the "used" country to compare against RDAP's "registered" country.
  ip_api = _static_ips.lookup_geo_basics(ip)
  out["ip_api"] = ip_api

  # Phase 2: every other source runs in parallel since they're
  # independent.
  with ThreadPoolExecutor(max_workers=4) as ex:
    f_spamhaus = ex.submit(_quality_spamhaus, ip)
    f_scamalytics = ex.submit(_quality_scamalytics, ip)
    f_native = ex.submit(_quality_native, ip, ip_api)
    f_stream = ex.submit(_streaming_unlock_extended) if include_streaming else None
    out["spamhaus"] = f_spamhaus.result()
    out["scamalytics"] = f_scamalytics.result()
    out["native"] = f_native.result()
    out["streaming"] = f_stream.result() if f_stream else []
  out["finished_at"] = time.time()
  out["wall_time_seconds"] = round(out["finished_at"] - out["started_at"], 2)
  return out


__all__ = [
  "run_speed_test",
  "run_quality_report",
]
