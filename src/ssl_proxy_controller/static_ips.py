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


def regex_parse_lines(text: str) -> list[dict[str, Any]]:
  """Pure-regex fallback that splits on lines and pulls out each row's
  IP, port, protocol, country and provider hints.
  """
  out: list[dict[str, Any]] = []
  for raw in text.splitlines():
    line = raw.strip()
    if not line or line.startswith("#"):
      continue
    ip: str | None = None
    port: int | None = None
    after: str = line
    # Try bracketed IPv6 first.
    bracket = _IPV6_BRACKET_RE.search(line)
    if bracket:
      ip = bracket.group(1)
      port = int(bracket.group(2)) if bracket.group(2) else None
      after = line[bracket.end() :]
    if ip is None:
      # IPv4 takes precedence over plain IPv6 since the latter often
      # appears as a literal address with embedded ports we'd miss.
      v4 = _IP_RE.search(line)
      v6 = _IPV6_DOUBLECOLON_RE.search(line) if not v4 else None
      ip_match = v4 or v6 or _IPV6_RE.search(line)
      if not ip_match:
        continue
      ip = ip_match.group(0)
      after = line[ip_match.end() :]
      port_match = _PORT_RE.match(after) or _PORT_RE.search(after)
      if port_match:
        try:
          port = int(port_match.group(1))
        except ValueError:
          port = None
    if port is not None and not (0 < port < 65536):
      port = None
    protocol = _detect_protocol(line)
    country = _detect_country(line)
    provider = _detect_provider(line)
    out.append({
      "ip": ip,
      "port": port,
      "protocol": protocol,
      "country": country,
      "provider": provider,
      "label": None,
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
  "null)}. The user's text may contain country names in any language "
  "(English, Chinese, etc.) — translate to canonical English country "
  "names. Protocols include tcp, udp, http, https, ssh, socks5, "
  "shadowsocks, trojan, vmess, vless, wireguard, openvpn, hysteria2, "
  "icmp. Default protocol to 'tcp' when unknown. Respond with ONLY the "
  "JSON array, no prose, no code fence."
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

  if len(text) > _AI_MAX_INPUT_CHARS:
    LOGGER.warning(
      "bulk parse input is %d chars, truncating to %d for AI request",
      len(text), _AI_MAX_INPUT_CHARS,
    )
  ai_text = text[:_AI_MAX_INPUT_CHARS]

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
    return out

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

  return regex_parse_lines(text), "regex"


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
  country = _coerce_ai_string(rec.get("country"))
  provider = _coerce_ai_string(rec.get("provider"))
  label = _coerce_ai_string(rec.get("label"))
  return {
    "ip": ip,
    "port": port,
    "protocol": protocol,
    "country": country,
    "provider": provider,
    "label": label,
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
  for url in (
    f"https://ipapi.co/{ip}/json/",
    f"http://ip-api.com/json/{ip}",
  ):
    try:
      status, _, body = _http_get(url, timeout=6.0)
      if status != 200:
        continue
      data = json.loads(body)
      if "error" in data and data.get("error"):
        continue
      return {
        "ip": ip,
        "country": data.get("country_name") or data.get("country"),
        "country_code": data.get("country_code") or data.get("countryCode"),
        "region": data.get("region") or data.get("regionName"),
        "city": data.get("city"),
        "org": data.get("org") or data.get("isp"),
        "asn": data.get("asn") or data.get("as"),
        "lat": data.get("latitude") or data.get("lat"),
        "lon": data.get("longitude") or data.get("lon"),
        "raw_source": url,
      }
    except Exception:
      continue
  return {"ip": ip, "error": "geo lookup unavailable"}


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
]
