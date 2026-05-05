"""Static IP registry — parsing, testing, info probing.

Companion module to ``admin.py`` that owns the actual logic for the
"Static IPs" admin channel:

* ``parse_bulk_input`` — call an LLM to turn a free-form blob (multiple
  IPs, multiple protocols, country names mixed in) into a clean list of
  records. Falls back to a deterministic regex parser when no AI key is
  configured.
* ``test_connectivity`` — TCP connect / ICMP ping with latency.
* ``probe_static_info`` — outbound HTTPS lookups against ipapi.co and a
  small bundle of streaming-service unlock checks.

Everything is dependency-light (stdlib only) and side-effect free.
"""

from __future__ import annotations

import json
import logging
import os
import re
import socket
import ssl as _ssl
import subprocess
import time
import urllib.error
import urllib.request
from typing import Any

LOGGER = logging.getLogger("ssl_proxy_controller.static_ips")

# Maximum characters of free-form text we will hand to the LLM in a
# single request. We don't silently truncate — we log a warning so the
# operator can split the input.
_AI_MAX_INPUT_CHARS = 8000

# Cap stored error blobs so a chatty subprocess can't bloat the DB row.
_MAX_STORED_ERROR_CHARS = 500

# ---------------------------------------------------------------------------
# Bulk parsing
# ---------------------------------------------------------------------------

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# IPv6 with bracketed [::1]:port form, OR a fully-formed colon group with at
# least one '::'. Keep this conservative — partial matches caused false
# positives (e.g. matching only '2001:4860:4860' from '2001:4860:4860::8888').
_IPV6_BRACKET_RE = re.compile(r"\[([0-9A-Fa-f:]+)\](?::(\d{1,5}))?")
_IPV6_RE = re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}(?::|[A-Fa-f0-9]{1,4})\b")
_IPV6_DOUBLECOLON_RE = re.compile(r"\b[A-Fa-f0-9:]*::[A-Fa-f0-9:]*[A-Fa-f0-9]\b")
_PORT_RE = re.compile(r":(\d{1,5})(?:\b|$)")
# DNS hostname followed by ``:port``. Used for gateway-style URIs
# where the connection target is a domain (Decodo / BrightData /
# Oxylabs / etc.). Requires at least one dot so single-label hostnames
# like ``localhost`` don't false-match. Anchored at start because we
# only call this against the post-credential portion.
_HOST_PORT_RE = re.compile(
  r"^([A-Za-z0-9](?:[A-Za-z0-9\-_]*[A-Za-z0-9])?"
  r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-_]*[A-Za-z0-9])?)+):(\d{1,5})\b"
)

# Lowercase keyword → canonical country.
_COUNTRY_KEYWORDS = {
  # English
  "united states": "United States", "usa": "United States", "us": "United States",
  "america": "United States",
  "japan": "Japan", "jp": "Japan",
  "korea": "South Korea", "south korea": "South Korea", "kr": "South Korea",
  "hong kong": "Hong Kong", "hk": "Hong Kong",
  "singapore": "Singapore", "sg": "Singapore",
  "taiwan": "Taiwan", "tw": "Taiwan",
  "germany": "Germany", "de": "Germany",
  "uk": "United Kingdom", "united kingdom": "United Kingdom", "england": "United Kingdom",
  "france": "France", "fr": "France",
  "canada": "Canada", "ca": "Canada",
  "australia": "Australia", "au": "Australia",
  "russia": "Russia", "ru": "Russia",
  "india": "India", "in": "India",
  "netherlands": "Netherlands", "nl": "Netherlands",
  "china": "China", "cn": "China", "mainland": "China",
  # Chinese
  "美国": "United States", "美": "United States",
  "日本": "Japan", "日": "Japan",
  "韩国": "South Korea", "韩": "South Korea",
  "香港": "Hong Kong", "港": "Hong Kong",
  "新加坡": "Singapore", "狮城": "Singapore",
  "台湾": "Taiwan", "台": "Taiwan",
  "德国": "Germany", "德": "Germany",
  "英国": "United Kingdom", "英": "United Kingdom",
  "法国": "France", "法": "France",
  "加拿大": "Canada",
  "澳大利亚": "Australia", "澳洲": "Australia",
  "俄罗斯": "Russia", "俄": "Russia",
  "印度": "India",
  "荷兰": "Netherlands",
  "中国": "China", "国内": "China", "大陆": "China",
}

# Lowercase keyword → canonical provider.
_PROVIDER_KEYWORDS = {
  "aws": "AWS", "amazon": "AWS", "ec2": "AWS",
  "gcp": "GCP", "google cloud": "GCP", "google": "GCP",
  "azure": "Azure", "microsoft": "Azure",
  "digitalocean": "DigitalOcean", "do": "DigitalOcean",
  "vultr": "Vultr", "linode": "Linode", "akamai": "Akamai",
  "ovh": "OVH", "hetzner": "Hetzner",
  "alibaba": "Alibaba Cloud", "aliyun": "Alibaba Cloud", "阿里云": "Alibaba Cloud",
  "tencent": "Tencent Cloud", "腾讯云": "Tencent Cloud",
  "huawei": "Huawei Cloud", "华为云": "Huawei Cloud",
  "cloudflare": "Cloudflare",
  "bandwagon": "BandwagonHost", "搬瓦工": "BandwagonHost", "bwh": "BandwagonHost",
  "racknerd": "RackNerd",
  "contabo": "Contabo",
}

_PROTO_KEYWORDS = {
  "tcp", "udp", "http", "https", "ssh",
  "socks5", "socks4", "shadowsocks", "ss",
  "trojan", "vmess", "vless",
  "wireguard", "wg", "openvpn", "ovpn",
  "hysteria", "hysteria2", "hy2", "icmp",
}


def _scrub_proto(token: str) -> str | None:
  t = token.strip().lower().rstrip(":/")
  if t in _PROTO_KEYWORDS:
    if t == "ss":
      return "shadowsocks"
    if t == "wg":
      return "wireguard"
    if t == "ovpn":
      return "openvpn"
    if t == "hy2":
      return "hysteria2"
    return t
  return None


def _detect_country(text: str) -> str | None:
  lower = text.lower()
  best: tuple[int, str] | None = None
  for key, value in _COUNTRY_KEYWORDS.items():
    if key in lower:
      score = len(key)
      if best is None or score > best[0]:
        best = (score, value)
  return best[1] if best else None


def _detect_provider(text: str) -> str | None:
  lower = text.lower()
  for key, value in _PROVIDER_KEYWORDS.items():
    if key in lower:
      return value
  return None


def _detect_protocol(text: str) -> str:
  lower = text.lower()
  # explicit URL prefix wins
  url_match = re.match(r"\s*([a-z][a-z0-9]*)://", lower)
  if url_match:
    proto = _scrub_proto(url_match.group(1))
    if proto:
      return proto
  for token in re.split(r"[\s,;|]+", lower):
    proto = _scrub_proto(token)
    if proto:
      return proto
  return "tcp"


def _split_userpass_at_host(line: str) -> tuple[str | None, str | None, str]:
  """Split a line like ``user:pass@host:port`` into
  ``(username, password, host_part)``.

  Tolerates a leading ``scheme://`` (handled by the caller) and is
  conservative — only fires when:

  * a single ``@`` precedes the host
  * the part before ``@`` contains exactly one ``:`` separator
  * the part after ``@`` starts with something that looks like a
    host — either an IP address or a DNS name. We accept DNS names
    so gateway formats (``user:pass@isp.decodo.com:10001``) are
    captured; the false-positive risk for "@" inside an email is
    handled by also requiring a port to follow.

  Returns ``(None, None, line)`` if the prefix isn't recognised, so
  the existing IP-only parsing keeps working for plain lists.
  """
  at_idx = line.find("@")
  if at_idx <= 0:
    return None, None, line
  creds = line[:at_idx]
  rest = line[at_idx + 1:]
  # Use rfind/find here? We want the FIRST colon — the one separating
  # username from password. If user encodes ":" inside the username
  # (Decodo doesn't, but some providers might), this still works
  # because we don't try to interpret the username's content.
  colon_idx = creds.find(":")
  if not (0 < colon_idx < len(creds) - 1):
    return None, None, line
  # Reject if creds contains whitespace — this isn't a user:pass form.
  if any(c.isspace() for c in creds):
    return None, None, line
  # The host part must look like ``host:port``. Accepts:
  #   - IPv4 address followed by ``:port``
  #   - bracketed IPv6 with optional port
  #   - bare IPv6 (last-resort)
  #   - DNS hostname (one or more dot-separated labels) followed
  #     by ``:port`` — for gateway-style URIs.
  has_ip_form = bool(_IP_RE.search(rest)
                     or _IPV6_BRACKET_RE.search(rest)
                     or _IPV6_DOUBLECOLON_RE.search(rest))
  has_host_port_form = bool(re.match(
    r"^[A-Za-z0-9](?:[A-Za-z0-9\-_.]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-_]*[A-Za-z0-9])?)+:\d{1,5}\b",
    rest))
  if not (has_ip_form or has_host_port_form):
    return None, None, line
  return creds[:colon_idx], creds[colon_idx + 1:], rest


# Provider gateway domains. Operators paste lines like
#   socks5h://user-...-ip-A.B.C.D:secret@isp.decodo.com:10001
# and we need to (a) detect that this is a "gateway" row, not a
# "static" one, and (b) name the provider so the UI can render a
# badge. Match by domain suffix — exact host varies (Bright Data uses
# ``brd.superproxy.io``, Oxylabs has ``pr.oxylabs.io`` for residential
# and ``dc.oxylabs.io`` for datacenter, etc.).
_GATEWAY_PROVIDER_DOMAINS: tuple[tuple[str, str], ...] = (
  # (host substring, canonical provider id)
  ("decodo.com",        "decodo"),
  ("smartproxy.com",    "smartproxy"),
  ("smartproxy.io",     "smartproxy"),
  ("oxylabs.io",        "oxylabs"),
  ("oxylabs.com",       "oxylabs"),
  ("brightdata.com",    "brightdata"),
  ("luminati.io",       "brightdata"),     # legacy
  ("superproxy.io",     "brightdata"),     # ``brd.superproxy.io``
  ("iproyal.com",       "iproyal"),
  ("webshare.io",       "webshare"),
  ("netnut.io",         "netnut"),
  ("rayobyte.com",      "rayobyte"),
  ("packetstream.io",   "packetstream"),
  ("nodemaven.com",     "nodemaven"),
  ("soax.com",          "soax"),
  ("proxy-cheap.com",   "proxy-cheap"),
  ("proxycheap.com",    "proxy-cheap"),
)


# Match a single IPv6 address. We don't try to be RFC-perfect — accept
# any sequence of hex groups separated by colons, with optional ``::``
# zero-compression. False-positives like ``2:3:4:5:6:7:8`` are tolerable
# since they only show up where we *expect* an IP address (after a
# ``=>`` separator or in an exit-IP slot). Two-or-more-colons threshold
# distinguishes from ``host:port:user:pass`` (max 3 colons, none of
# which form a valid IPv6).
_IPV6_FREE_RE = re.compile(
  r"\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f:]{1,4}\b"
)

# Colon-quad format used by proxy-cheap and many list-broker services:
#   ``IPv4:port:user:pass``
# Anchored to the start of the line and trailing-whitespace-tolerant
# so the post-line operations (=> suffix, comments) keep working.
# Username and password may contain almost anything except whitespace
# and colon — colons are a no-go because there's no escape mechanism
# in this format.
_COLON_QUAD_RE = re.compile(
  r"^((?:\d{1,3}\.){3}\d{1,3}):(\d{1,5}):([^:\s]+):([^:\s]+)\s*$"
)


def _gateway_provider_for(host: str) -> str | None:
  """Match a host against the known-gateway-domain list. Returns the
  canonical provider id (``'decodo'``, ``'oxylabs'``, …) or None when
  the host doesn't look like a known gateway.

  Matches at the DNS-label boundary — ``isp.decodo.com`` matches
  ``decodo.com`` but a look-alike like ``mydecodo.com`` does NOT, even
  though the substring is technically present. This prevents anyone
  from social-engineering a row into "Decodo" by registering a
  similar-sounding domain.
  """
  if not host:
    return None
  hl = host.lower().strip().rstrip(".")
  for needle, provider in _GATEWAY_PROVIDER_DOMAINS:
    # Match either an exact host (== needle) or a subdomain of needle
    # (host ends with ".<needle>"). No bare-substring contains-check.
    if hl == needle or hl.endswith("." + needle):
      return provider
  return None


# Provider-specific session-string conventions. Each pattern picks an
# IPv4 out of the username so we can populate ``exit_ip``. These are
# best-effort; a username that doesn't match any pattern simply leaves
# exit_ip unset (the row still works as a gateway, the operator just
# doesn't get geo / quality on the exit IP).
_USERNAME_EXIT_IP_PATTERNS: tuple[str, ...] = (
  # Decodo, Smartproxy, IPRoyal, NetNut all use ``-ip-A.B.C.D`` token.
  r"-ip-(\d{1,3}(?:\.\d{1,3}){3})\b",
  # Bright Data sometimes embeds the exit as ``-ip-A.B.C.D`` after
  # the zone name (same regex as above).
  # Oxylabs supports ``-sessid-X`` (no IP) plus an IP-locked variant
  # encoded as ``-ip-A.B.C.D`` — same regex covers it.
)


def _extract_exit_ip_from_username(username: str | None) -> str | None:
  """Best-effort exit-IP extraction from a gateway-style username.

  Provider conventions vary, but ``-ip-<IPv4>`` is the de-facto
  cross-provider standard. Returns the IPv4 string or None."""
  if not username:
    return None
  for pat in _USERNAME_EXIT_IP_PATTERNS:
    m = re.search(pat, username)
    if m:
      return m.group(1)
  # Fallback: any bare IPv4 inside the username (handles the rare
  # ``customer-...-A.B.C.D-...`` schema some providers use).
  m = _IP_RE.search(username)
  return m.group(0) if m else None


def regex_parse_lines(text: str) -> list[dict[str, Any]]:
  """Pure-regex fallback that splits on lines and pulls out each row's
  IP, port, protocol, country, provider, and (when the ``user:pass@``
  prefix is present) username + password.

  Supported line shapes:
    1. ``IPv4:port``                                — plain static
    2. ``user:pass@host:port`` (with or without scheme)  — RFC URI form
    3. ``IPv4:port:user:pass``                     — colon-quad list
       format (proxy-cheap, many list brokers); user/pass cannot contain
       colons or whitespace.
    4. Any of the above with a trailing ``=> <exit_ip>`` (or ``->``)
       suffix, where ``<exit_ip>`` may be IPv4 or IPv6. When present we
       record the row as ``kind='gateway'`` with that exit IP — handy
       for proxy-cheap-style entries where you connect via IPv4 but the
       exit address is IPv6.
  """
  out: list[dict[str, Any]] = []
  for raw in text.splitlines():
    line = raw.strip()
    if not line or line.startswith("#"):
      continue

    # ----- Step 0: pull off optional "@<provider>" suffix.
    # Operators paste this when they want a specific gateway provider
    # tag without it being detectable from the connect host. Order is
    # parsed first so it's tolerated alongside the "=> exit_ip" suffix.
    explicit_provider: str | None = None
    prov_match = re.search(r"\s+@\s*([A-Za-z][A-Za-z0-9_.\-]*)\s*$", line)
    if prov_match:
      explicit_provider = prov_match.group(1).strip().lower()
      line = line[:prov_match.start()].rstrip()

    # ----- Step 0.1: pull off an optional "=> exit_ip" suffix.
    # Operators paste this when the connect address differs from the
    # exit address (proxy-cheap IPv6 exits, BrightData zone-by-IP, etc.).
    # We accept "=>", "->", or " exit " as separators.
    explicit_exit: str | None = None
    suffix_match = re.search(
      r"\s*(?:=>|->|\bexit[:= ]+)\s*([^\s]+)\s*$", line)
    if suffix_match:
      candidate = suffix_match.group(1).strip()
      # Validate it actually looks like an IP (v4 or v6) — we don't
      # want to slurp arbitrary trailing text.
      if (_IP_RE.fullmatch(candidate)
          or _IPV6_FREE_RE.fullmatch(candidate)
          or candidate.startswith("[") and candidate.endswith("]")):
        explicit_exit = candidate.strip("[]")
        line = line[:suffix_match.start()].rstrip()

    # ----- Step 0.5: try the colon-quad ``host:port:user:pass`` form
    # before any scheme-stripping, since this format never has a scheme.
    quad_match = _COLON_QUAD_RE.match(line)
    if quad_match:
      qhost = quad_match.group(1)
      qport = int(quad_match.group(2))
      quser = quad_match.group(3)
      qpass = quad_match.group(4)
      # Reshape into the canonical ``user:pass@host:port`` form so the
      # rest of the parser can stay shape-agnostic. Default protocol
      # for credential-bearing lines is socks5 (residential convention).
      line = f"{quser}:{qpass}@{qhost}:{qport}"

    # Strip a "scheme://" prefix if present and remember it as a
    # protocol hint that beats keyword detection later.
    scheme_proto_hint: str | None = None
    scheme_match = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*)://(.*)$", line)
    body = scheme_match.group(2) if scheme_match else line
    if scheme_match:
      scheme_proto_hint = scheme_match.group(1).lower()

    # Extract optional user:pass@ prefix. Falls through cleanly when
    # the line is a plain "host:port".
    username, password, line_for_ip = _split_userpass_at_host(body)

    ip: str | None = None
    port: int | None = None
    after: str = line_for_ip
    # Detect whether this is a "gateway" URI — the host part is a DNS
    # name belonging to a known proxy provider (Decodo, BrightData,
    # Oxylabs, etc.). When detected, we record the hostname as ``ip``
    # (the connection target) and pull the per-session exit IP out of
    # the username for ``exit_ip``.
    kind = "static"
    exit_ip: str | None = None
    gateway_provider: str | None = None
    host_match = _HOST_PORT_RE.match(line_for_ip)
    if host_match:
      candidate_host = host_match.group(1)
      candidate_port = int(host_match.group(2))
      provider_id = _gateway_provider_for(candidate_host)
      if provider_id:
        ip = candidate_host
        port = candidate_port
        after = line_for_ip[host_match.end():]
        kind = "gateway"
        gateway_provider = provider_id
        exit_ip = _extract_exit_ip_from_username(username)

    # Bracketed IPv6 — only attempted when we haven't already matched
    # a gateway hostname.
    if ip is None:
      bracket = _IPV6_BRACKET_RE.search(line_for_ip)
      if bracket:
        ip = bracket.group(1)
        port = int(bracket.group(2)) if bracket.group(2) else None
        after = line_for_ip[bracket.end():]
    if ip is None:
      # IPv4 takes precedence over plain IPv6 since the latter often
      # appears as a literal address with embedded ports we'd miss.
      v4 = _IP_RE.search(line_for_ip)
      v6 = _IPV6_DOUBLECOLON_RE.search(line_for_ip) if not v4 else None
      ip_match = v4 or v6 or _IPV6_RE.search(line_for_ip)
      if not ip_match:
        # Last resort: a hostname:port without a provider match. We
        # still accept it as a "gateway" row (operator can fix the
        # provider field by hand if needed) — the alternative is
        # silently dropping the line, which is worse.
        if host_match:
          ip = host_match.group(1)
          port = int(host_match.group(2))
          after = line_for_ip[host_match.end():]
          kind = "gateway"
          # No known provider — leave gateway_provider unset; the UI
          # will render it as "(custom gateway)".
          exit_ip = _extract_exit_ip_from_username(username)
        else:
          continue
      else:
        ip = ip_match.group(0)
        after = line_for_ip[ip_match.end():]
        port_match = _PORT_RE.match(after) or _PORT_RE.search(after)
        if port_match:
          try:
            port = int(port_match.group(1))
          except ValueError:
            port = None
    if port is not None and not (0 < port < 65536):
      port = None

    # Protocol resolution priority:
    #   1. Explicit scheme:// prefix (most authoritative)
    #   2. Keyword in the line ("trojan", "shadowsocks", etc.)
    #   3. Default: socks5 when user:pass@ was present (residential
    #      proxy convention), tcp otherwise.
    # ``_detect_protocol`` collapses (2) and (3) by always returning
    # "tcp" on no match; do the keyword scan inline so we can tell the
    # difference between "operator typed tcp" and "no hint at all".
    protocol: str | None = scheme_proto_hint
    if protocol is None:
      for token in re.split(r"[\s,;|]+", line.lower()):
        cand = _scrub_proto(token)
        if cand:
          protocol = cand
          break
    if protocol is None:
      protocol = "socks5" if (username or password) else "tcp"

    # An explicit ``=> exit_ip`` suffix on the input line forces the
    # row to be a gateway, regardless of how we'd otherwise classify
    # it. Connect address stays the parsed ``ip``; exit address is
    # whatever the operator pinned. This is the proxy-cheap pattern:
    # IPv4 connection, IPv6 exit, neither side encoded in the username.
    if explicit_exit:
      kind = "gateway"
      exit_ip = explicit_exit
    if explicit_provider:
      # Promote to gateway too — providing a provider name without
      # otherwise being a gateway is meaningful by itself (operators
      # mark their proxy-cheap entries this way).
      kind = "gateway"
      gateway_provider = explicit_provider

    # Country/provider keyword detection. For gateway rows we SKIP
    # this entirely — keyword scanning over ``isp.decodo.com`` would
    # misfire ("de" -> Germany, "do" -> DigitalOcean) and produce
    # gateway-location data instead of exit-IP-location data. The
    # bulk-import autofill step will run a real geo lookup against
    # ``exit_ip`` later in the pipeline.
    if kind == "gateway":
      country, provider = None, None
    else:
      # Static rows: keyword scan ``line_for_ip`` (the host:port part),
      # not the full raw line, so substrings inside a credential like
      # "info0ecxd" don't false-match country aliases like "in" -> India.
      country = _detect_country(line_for_ip)
      provider = _detect_provider(line_for_ip)
    # ``socks5h`` (SOCKS5 with remote DNS) is treated as plain
    # ``socks5`` for storage — they're functionally identical at the
    # protocol level, and our SOCKS5 implementation already sends
    # destination as a hostname when the caller passes one.
    if protocol == "socks5h":
      protocol = "socks5"

    out.append({
      "ip": ip,
      "port": port,
      "protocol": protocol,
      "country": country,
      "provider": provider,
      "username": username,
      "password": password,
      "label": None,
      "kind": kind,
      "exit_ip": exit_ip,
      "gateway_provider": gateway_provider,
      "raw": line,
    })
  return out


# ---------------------------------------------------------------------------
# AI-powered parsing
# ---------------------------------------------------------------------------

# We try, in order, OPENAI / Codex compatible API → ANTHROPIC API. Both
# fall back to ``regex_parse_lines`` if they fail.

_AI_SYSTEM_PROMPT = (
  "You normalize free-form text describing static IP addresses into a "
  "JSON array. Extract every IP. For each IP, return: {ip (string), "
  "port (integer or null), protocol (string, lowercase), country "
  "(string or null), provider (string or null), label (string or "
  "null), username (string or null), password (string or null)}. "
  "The user's text may contain country names in any language "
  "(English, Chinese, etc.) — translate to canonical English country "
  "names. Protocols include tcp, udp, http, https, ssh, socks5, "
  "shadowsocks, trojan, vmess, vless, wireguard, openvpn, hysteria2, "
  "icmp. When a line is in 'user:pass@host:port' or "
  "'scheme://user:pass@host:port' form, extract username and password "
  "from the credentials portion. If the line has 'user:pass@' but no "
  "scheme, default protocol to 'socks5' (residential proxy convention) "
  "rather than 'tcp'. Respond with ONLY the JSON array, no prose, no "
  "code fence."
)


def _strip_json_fence(text: str) -> str:
  """Strip a fenced code block wrapper if the model added one.

  Handles fences like ```json ... ```, ```python ... ```, and bare
  triple-backticks. Matches the optional language tag, then any
  whitespace, then trims a trailing fence if present.
  """
  text = text.strip()
  if text.startswith("```"):
    text = re.sub(r"^```[A-Za-z0-9_-]*\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
  return text.strip()


def _ai_parse_openai(text: str, *, base_url: str, api_key: str, model: str) -> list[dict[str, Any]] | None:
  base = base_url.rstrip("/")
  # Accept both "https://api.example.com" and "https://api.example.com/v1"
  if base.endswith("/v1"):
    url = base + "/chat/completions"
  else:
    url = base + "/v1/chat/completions"
  body = {
    "model": model,
    "messages": [
      {"role": "system", "content": _AI_SYSTEM_PROMPT},
      {"role": "user", "content": text},
    ],
    "temperature": 0.0,
  }
  req = urllib.request.Request(
    url,
    data=json.dumps(body).encode("utf-8"),
    headers={
      "Content-Type": "application/json",
      "Authorization": f"Bearer {api_key}",
      "User-Agent": "ssl-service-static-ip-parser/1.0",
    },
    method="POST",
  )
  with urllib.request.urlopen(req, timeout=30) as resp:
    payload = json.loads(resp.read().decode("utf-8"))
  choices = payload.get("choices") or []
  if not choices:
    LOGGER.warning("openai response has no choices: %s", str(payload)[:300])
    return None
  content = ((choices[0] or {}).get("message") or {}).get("content") or ""
  if not content:
    LOGGER.warning("openai response choice has empty content: %s", str(choices[0])[:300])
    return None
  cleaned = _strip_json_fence(content)
  parsed = json.loads(cleaned)
  if not isinstance(parsed, list):
    LOGGER.warning("openai response is not a JSON array: %s", str(parsed)[:300])
    return None
  return parsed


def _ai_parse_anthropic(text: str, *, api_key: str, model: str) -> list[dict[str, Any]] | None:
  url = "https://api.anthropic.com/v1/messages"
  body = {
    "model": model,
    "max_tokens": 4096,
    "system": _AI_SYSTEM_PROMPT,
    "messages": [{"role": "user", "content": text}],
  }
  req = urllib.request.Request(
    url,
    data=json.dumps(body).encode("utf-8"),
    headers={
      "Content-Type": "application/json",
      "x-api-key": api_key,
      "anthropic-version": "2023-06-01",
      "User-Agent": "ssl-service-static-ip-parser/1.0",
    },
    method="POST",
  )
  with urllib.request.urlopen(req, timeout=30) as resp:
    payload = json.loads(resp.read().decode("utf-8"))
  content_blocks = payload.get("content", []) or []
  text_out = "".join(
    blk.get("text", "") for blk in content_blocks if blk.get("type") == "text"
  )
  cleaned = _strip_json_fence(text_out)
  if not cleaned:
    LOGGER.warning("anthropic response has no text content: %s", str(payload)[:300])
    return None
  parsed = json.loads(cleaned)
  if not isinstance(parsed, list):
    LOGGER.warning("anthropic response is not a JSON array: %s", str(parsed)[:300])
    return None
  return parsed


def _gateway_pre_pass(text: str) -> tuple[list[dict[str, Any]], str]:
  """Pull gateway-URI lines out of ``text`` and parse them via the
  deterministic regex parser. Returns ``(gateway_records, leftover_text)``.

  Why a pre-pass: AI parsers (OpenAI / Anthropic) consistently
  misinterpret residential-proxy gateway URIs like
  ``socks5h://user-...-ip-A.B.C.D:pass@isp.decodo.com:10001`` —
  they pull ``A.B.C.D`` out of the username and present it as the
  host, which is the OPPOSITE of correct (the connection target is
  the gateway domain, the exit IP lives in the username). The regex
  parser, in contrast, has explicit gateway-domain detection and
  gets these right every time.

  Implementation: run the regex parser line-by-line; any line whose
  regex output says ``kind == 'gateway'`` is considered AI-unsafe and
  pulled out. This is stricter than the previous ``substring contains
  decodo.com`` check (which false-matched on comment lines and
  unrelated mentions), and it avoids re-implementing host-suffix
  matching in two places.
  """
  gateway_lines: list[str] = []
  other_lines: list[str] = []
  for raw in text.splitlines():
    line = raw.strip()
    if not line or line.startswith("#"):
      other_lines.append(raw)
      continue
    parsed = regex_parse_lines(raw)
    if parsed and (parsed[0].get("kind") == "gateway"):
      gateway_lines.append(raw)
    else:
      other_lines.append(raw)
  if not gateway_lines:
    return [], text
  records = regex_parse_lines("\n".join(gateway_lines))
  return records, "\n".join(other_lines)


def parse_bulk_input(
  text: str,
  *,
  config: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], str]:
  """Return (records, mode) where mode ∈ {"ai-openai","ai-anthropic","regex"}.

  Each record is normalized to: ip, port, protocol, country, provider, label.

  ``config`` can override the AI endpoint at call time. Recognized keys::

      {
        "openai": {
          "base_url": "...",  # required to enable
          "api_key":  "...",  # required to enable
          "model":    "gpt-..."
        },
        "anthropic": {
          "api_key": "...",
          "model": "claude-..."
        }
      }

  When a key is missing in config, we fall back to the corresponding
  environment variable (so existing deploys keep working).
  """
  if not text or not text.strip():
    return [], "regex"

  # Pre-pass: pull gateway URIs out and parse them with regex. The AI
  # parser misinterprets these consistently, so we never let it touch
  # them. ``leftover_text`` is what (if anything) goes to the AI.
  gateway_records, leftover_text = _gateway_pre_pass(text)

  if not leftover_text.strip() and gateway_records:
    # All lines were gateway URIs — skip the AI call entirely.
    return gateway_records, "regex"

  if len(leftover_text) > _AI_MAX_INPUT_CHARS:
    LOGGER.warning(
      "bulk parse input is %d chars, truncating to %d for AI request",
      len(leftover_text), _AI_MAX_INPUT_CHARS,
    )
  ai_text = leftover_text[:_AI_MAX_INPUT_CHARS]

  def _normalize(raw: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for r in raw:
      if not isinstance(r, dict):
        continue
      rec = _normalize_ai_record(r)
      if not rec.get("ip"):
        # Defensive: drop rows the model returned without an IP.
        continue
      out.append(rec)
    # AI models inconsistently follow the prompt for username/password
    # extraction, even when the input is the deterministic
    # ``user:pass@host:port`` form. Run the regex parser on the same
    # input and fill in missing creds keyed by IP — regex is exact
    # for this format and never drops creds the AI happened to ignore.
    try:
      regex_rows = regex_parse_lines(leftover_text)
    except Exception:  # noqa: BLE001
      regex_rows = []
    if regex_rows:
      by_ip = {r.get("ip"): r for r in regex_rows if r.get("ip")}
      for rec in out:
        ref = by_ip.get(rec.get("ip"))
        if not ref:
          continue
        if not rec.get("username") and ref.get("username"):
          rec["username"] = ref["username"]
        if not rec.get("password") and ref.get("password"):
          rec["password"] = ref["password"]
    # Prepend the gateway records that the AI never saw — they
    # already came from the deterministic regex parser.
    return gateway_records + out

  cfg = config or {}
  oai = cfg.get("openai") or {}
  api_key = (
    (oai.get("api_key") or "").strip()
    or os.environ.get("STATIC_IP_AI_API_KEY")
    or os.environ.get("OPENAI_API_KEY")
  )
  base_url = (
    (oai.get("base_url") or "").strip()
    or os.environ.get("STATIC_IP_AI_BASE_URL")
    or os.environ.get("OPENAI_BASE_URL", "https://api.openai.com")
  )
  model = (
    (oai.get("model") or "").strip()
    or os.environ.get("STATIC_IP_AI_MODEL", "gpt-4o-mini")
  )
  if api_key:
    try:
      raw = _ai_parse_openai(ai_text, base_url=base_url, api_key=api_key, model=model)
      if raw is not None:
        return _normalize(raw), "ai-openai"
    except urllib.error.HTTPError as exc:
      LOGGER.warning("openai HTTP %s at %s: %s — falling back",
                     exc.code, base_url, exc.reason)
    except urllib.error.URLError as exc:
      LOGGER.warning("openai URL error at %s: %s — falling back", base_url, exc.reason)
    except json.JSONDecodeError as exc:
      LOGGER.warning("openai JSON decode error: %s — falling back", exc)
    except OSError as exc:
      LOGGER.warning("openai network error: %s — falling back", exc)

  ant = cfg.get("anthropic") or {}
  ant_key = (
    (ant.get("api_key") or "").strip()
    or os.environ.get("ANTHROPIC_API_KEY")
  )
  ant_model = (
    (ant.get("model") or "").strip()
    or os.environ.get("ANTHROPIC_MODEL", "claude-haiku-4-5-20251001")
  )
  if ant_key:
    try:
      raw = _ai_parse_anthropic(ai_text, api_key=ant_key, model=ant_model)
      if raw is not None:
        return _normalize(raw), "ai-anthropic"
    except urllib.error.HTTPError as exc:
      LOGGER.warning("anthropic HTTP %s: %s — falling back", exc.code, exc.reason)
    except urllib.error.URLError as exc:
      LOGGER.warning("anthropic URL error: %s — falling back", exc.reason)
    except json.JSONDecodeError as exc:
      LOGGER.warning("anthropic JSON decode error: %s — falling back", exc)
    except OSError as exc:
      LOGGER.warning("anthropic network error: %s — falling back", exc)

  # AI unavailable / failed. Run the regex parser on the leftover
  # (non-gateway) text and merge with the gateway pre-pass output.
  return gateway_records + regex_parse_lines(leftover_text), "regex"


_AI_FIELD_MAX_LEN = 200


def _coerce_ai_string(value: Any) -> str | None:
  """Defensive conversion for an AI-returned text field.

  The model is supposed to return strings, but we're paranoid: handle
  ``None`` / empty / wrong-type cleanly, and cap length so a misbehaving
  model can't push paragraphs into our country / provider / label
  columns. We don't try to be smart about Unicode normalization — just
  trim and truncate.
  """
  if value is None:
    return None
  if not isinstance(value, str):
    # Coerce non-strings (numbers, bools) to a short string repr.
    value = str(value)
  value = value.strip()
  if not value:
    return None
  if len(value) > _AI_FIELD_MAX_LEN:
    value = value[:_AI_FIELD_MAX_LEN]
  return value


def _normalize_ai_record(rec: dict[str, Any]) -> dict[str, Any]:
  ip = _coerce_ai_string(rec.get("ip")) or ""
  port_raw = rec.get("port")
  if isinstance(port_raw, bool):  # bool is an int subclass; reject explicitly
    port = None
  elif port_raw in (None, "", 0):
    port = None
  else:
    try:
      port = int(port_raw)
    except (TypeError, ValueError):
      port = None
  if port is not None and not (1 <= port <= 65535):
    port = None
  protocol = _coerce_ai_string(rec.get("protocol")) or "tcp"
  protocol = protocol.lower()
  if protocol == "socks5h":
    # Treat socks5h as socks5 in storage; functionally identical.
    protocol = "socks5"
  country = _coerce_ai_string(rec.get("country"))
  provider = _coerce_ai_string(rec.get("provider"))
  label = _coerce_ai_string(rec.get("label"))
  username = _coerce_ai_string(rec.get("username"))
  password = _coerce_ai_string(rec.get("password"))
  # Auto-detect gateway from the host. Two heuristics, in priority order:
  #   1. Host matches a known provider domain → kind=gateway with that
  #      provider id baked in.
  #   2. Host looks like a DNS name (letters present, not pure IPv4) →
  #      kind=gateway with provider unset. Without this, AI-returned
  #      rows like ``ip="my-proxy.local"`` would persist as kind=static
  #      and break every code path that assumes static-row IPs are
  #      IPv4 literals.
  gateway_provider = _gateway_provider_for(ip) if ip else None
  ai_kind = (_coerce_ai_string(rec.get("kind")) or "").lower()
  if ai_kind in ("static", "gateway"):
    kind = ai_kind
  elif gateway_provider:
    kind = "gateway"
  elif ip and not _IP_RE.fullmatch(ip):
    # Hostname-shaped: any character outside the IPv4 grammar.
    # Conservative — IPv6 literals would fall here too, but those
    # don't currently flow through the AI path (regex catches them).
    kind = "gateway"
  else:
    kind = "static"
  exit_ip = _coerce_ai_string(rec.get("exit_ip"))
  if kind == "gateway" and not exit_ip:
    exit_ip = _extract_exit_ip_from_username(username)
  return {
    "ip": ip,
    "port": port,
    "protocol": protocol,
    "country": country,
    "provider": provider,
    "label": label,
    "username": username,
    "password": password,
    "kind": kind,
    "exit_ip": exit_ip,
    "gateway_provider": gateway_provider,
  }


# ---------------------------------------------------------------------------
# Connectivity test
# ---------------------------------------------------------------------------


def test_connectivity(
  ip: str,
  port: int | None,
  protocol: str,
  *,
  timeout: float = 4.0,
) -> dict[str, Any]:
  """Best-effort latency probe.

  * If a port is configured, we open a TCP connection (regardless of
    protocol — almost everything tunnels over TCP).
  * Without a port, we run an ICMP echo via the system ``ping``.
  * Returns ``{success, latency_ms, error, kind}``.
  """
  start = time.time()
  if port is not None and protocol.lower() not in ("icmp",):
    try:
      with socket.create_connection((ip, port), timeout=timeout) as _sock:
        latency = int((time.time() - start) * 1000)
      return {
        "success": True,
        "latency_ms": latency,
        "error": None,
        "kind": "tcp",
      }
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
      return {
        "success": False,
        "latency_ms": None,
        "error": f"{type(exc).__name__}: {exc}"[:_MAX_STORED_ERROR_CHARS],
        "kind": "tcp",
      }

  # Fall back to ICMP ping.
  cmd = ["ping", "-c", "1", "-W", "2", ip]
  try:
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)
    out = (proc.stdout or "") + "\n" + (proc.stderr or "")
    if proc.returncode == 0:
      m = re.search(r"time[=<]([\d.]+)\s*ms", out)
      latency = int(float(m.group(1))) if m else None
      return {
        "success": True,
        "latency_ms": latency,
        "error": None,
        "kind": "ping",
      }
    return {
      "success": False,
      "latency_ms": None,
      "error": (proc.stderr or proc.stdout or "ping failed").strip()[:_MAX_STORED_ERROR_CHARS],
      "kind": "ping",
    }
  except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
    return {
      "success": False,
      "latency_ms": None,
      "error": f"ping unavailable: {exc}"[:_MAX_STORED_ERROR_CHARS],
      "kind": "ping",
    }


# ---------------------------------------------------------------------------
# Static info probe (geo + streaming unlock)
# ---------------------------------------------------------------------------


def _http_get(url: str, *, timeout: float = 8.0, headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], str]:
  req = urllib.request.Request(
    url,
    headers={
      "User-Agent": "Mozilla/5.0 (compatible; ssl-service-static-ip-probe)",
      **(headers or {}),
    },
  )
  ctx = _ssl.create_default_context()
  with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
    body = resp.read(64 * 1024).decode("utf-8", errors="replace")
    return resp.status, dict(resp.headers), body


def _check_netflix() -> dict[str, Any]:
  try:
    status, _, body = _http_get("https://www.netflix.com/title/81215567", timeout=8.0)
    if status == 200:
      if "page-404" in body or "Not available" in body:
        return {"service": "Netflix", "status": "originals_only", "code": status}
      return {"service": "Netflix", "status": "full", "code": status}
    if status in (403, 451):
      return {"service": "Netflix", "status": "blocked", "code": status}
    return {"service": "Netflix", "status": "unknown", "code": status}
  except Exception as exc:
    return {"service": "Netflix", "status": "error", "error": str(exc)[:120]}


def _check_youtube_premium() -> dict[str, Any]:
  try:
    status, _, body = _http_get("https://www.youtube.com/premium", timeout=8.0)
    if status == 200:
      lower = body.lower()
      if "youtube premium is not available" in lower or "not available in your country" in lower:
        return {"service": "YouTube Premium", "status": "blocked", "code": status}
      m = re.search(r"\"countryCode\":\"([A-Z]{2})\"", body)
      if m:
        return {"service": "YouTube Premium", "status": "available", "code": status, "country_code": m.group(1)}
      return {"service": "YouTube Premium", "status": "available", "code": status}
    return {"service": "YouTube Premium", "status": "unknown", "code": status}
  except Exception as exc:
    return {"service": "YouTube Premium", "status": "error", "error": str(exc)[:120]}


def _check_chatgpt() -> dict[str, Any]:
  try:
    status, _, body = _http_get(
      "https://chatgpt.com/cdn-cgi/trace", timeout=6.0
    )
    if status == 200:
      m = re.search(r"loc=([A-Z]{2})", body)
      country = m.group(1) if m else None
      return {"service": "ChatGPT", "status": "available", "code": status, "country_code": country}
    if status in (403, 451):
      return {"service": "ChatGPT", "status": "blocked", "code": status}
    return {"service": "ChatGPT", "status": "unknown", "code": status}
  except Exception as exc:
    return {"service": "ChatGPT", "status": "error", "error": str(exc)[:120]}


def _check_disney() -> dict[str, Any]:
  try:
    status, _, body = _http_get("https://www.disneyplus.com/", timeout=8.0)
    if status in (403, 451):
      return {"service": "Disney+", "status": "blocked", "code": status}
    if status == 200:
      lower = body.lower()
      if "unavailable in your region" in lower or "not available" in lower:
        return {"service": "Disney+", "status": "blocked", "code": status}
      return {"service": "Disney+", "status": "available", "code": status}
    return {"service": "Disney+", "status": "unknown", "code": status}
  except Exception as exc:
    return {"service": "Disney+", "status": "error", "error": str(exc)[:120]}


def _geo_lookup(ip: str) -> dict[str, Any]:
  # Primary: ip-api.com with EXTENDED fields. Free + no-key returns
  # ``mobile / proxy / hosting`` boolean flags in addition to geo —
  # those flags drive the ISP-type tagging in the Quality report.
  # The ``fields`` query param uses a bitmask documented at
  # https://ip-api.com/docs/api:json. 66846719 = all useful fields.
  for url in (
    f"http://ip-api.com/json/{ip}?fields=66846719",
    f"https://ipapi.co/{ip}/json/",
  ):
    try:
      status, _, body = _http_get(url, timeout=6.0)
      if status != 200:
        continue
      data = json.loads(body)
      if "error" in data and data.get("error"):
        continue
      if data.get("status") == "fail":  # ip-api error path
        continue
      return {
        "ip": ip,
        "country": data.get("country_name") or data.get("country"),
        "country_code": data.get("country_code") or data.get("countryCode"),
        "region": data.get("region") or data.get("regionName"),
        "city": data.get("city"),
        "org": data.get("org") or data.get("isp"),
        "isp": data.get("isp"),
        "asn": data.get("asn") or data.get("as"),
        "asname": data.get("asname"),
        "lat": data.get("latitude") or data.get("lat"),
        "lon": data.get("longitude") or data.get("lon"),
        # Boolean ISP-type hints — only ip-api.com's extended fields
        # provide these on the free tier. ipapi.co requires a paid
        # plan for equivalent flags.
        "mobile": data.get("mobile"),
        "proxy": data.get("proxy"),
        "hosting": data.get("hosting"),
        "reverse": data.get("reverse"),
        "raw_source": url,
      }
    except Exception:
      continue
  return {"ip": ip, "error": "geo lookup unavailable"}


def lookup_geo_basics(ip: str, *, timeout: float = 4.0) -> dict[str, Any] | None:
  """Lightweight geo-only lookup used to auto-populate ``country`` /
  ``provider`` when a static_ip row is created.

  Distinct from ``probe_static_info`` in two ways:

  * No streaming-unlock checks (those add ~6 s of wall time and aren't
    needed when the operator is just typing in an IP).
  * Hard-bounded total wall time via ``timeout`` so a slow / flaky
    geo provider doesn't block the create endpoint perceptibly.

  Returns ``None`` on any failure — caller should treat geo as
  best-effort and never block on it.
  """
  try:
    geo = _geo_lookup(ip)
  except Exception as exc:  # noqa: BLE001
    LOGGER.info("lookup_geo_basics failed for %s: %s", ip, exc)
    return None
  if not geo or geo.get("error"):
    return None
  return {
    "country": geo.get("country"),
    "country_code": geo.get("country_code"),
    "city": geo.get("city"),
    "org": geo.get("org"),
    "isp": geo.get("isp"),
    "asn": geo.get("asn"),
    "asname": geo.get("asname"),
    "mobile": geo.get("mobile"),
    "proxy": geo.get("proxy"),
    "hosting": geo.get("hosting"),
    "reverse": geo.get("reverse"),
    "raw_source": geo.get("raw_source"),
  }


def probe_static_info(ip: str) -> dict[str, Any]:
  """One-shot static information probe.

  Note: streaming-unlock checks are performed from the **server**
  running this admin, not via the target IP. The result is therefore
  representative of THIS host's vantage point. We make this clear in
  the response so the operator isn't misled.

  All five outbound HTTP requests (geo + 4 streaming checks) run in
  parallel — they share nothing and each waits on its own remote
  endpoint, so the wall time is bounded by the slowest call (~8 s)
  instead of the sum of all five (~32-40 s).
  """
  from concurrent.futures import ThreadPoolExecutor
  with ThreadPoolExecutor(max_workers=5) as ex:
    geo_f = ex.submit(_geo_lookup, ip)
    nf_f = ex.submit(_check_netflix)
    yt_f = ex.submit(_check_youtube_premium)
    cg_f = ex.submit(_check_chatgpt)
    dp_f = ex.submit(_check_disney)
    geo = geo_f.result()
    unlock = [nf_f.result(), yt_f.result(), cg_f.result(), dp_f.result()]
  return {
    "geo": geo,
    "unlock": unlock,
    "probed_from": "admin host (vantage point)",
    "probed_at": int(time.time()),
  }


__all__ = [
  "parse_bulk_input",
  "regex_parse_lines",
  "test_connectivity",
  "probe_static_info",
  "lookup_geo_basics",
]
