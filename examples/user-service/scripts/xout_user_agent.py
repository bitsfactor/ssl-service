#!/usr/bin/env python3
"""Xout user-agent sidecar.

Runs INSIDE each xout container (one per node). Two responsibilities:

1. Periodically pull the active-user list for this node from
   user-service ``/api/internal/xout/active-users?node_name=<this>``,
   merge it into ``/data/preset.json`` (vless inbounds get the user
   list assigned to ``users[]``), and trigger an xray restart when the
   set changes. (Restart is implemented as ``kill 1`` so the container
   PID-1 supervisor / docker restart-policy brings it back with the
   refreshed preset.)

2. Periodically scrape per-user uplink / downlink from xray's stats
   API (gRPC at 127.0.0.1:10085 — exposed by the existing entrypoint),
   compute deltas since the previous tick (with reset), and POST them
   to ``/api/internal/xout/report-traffic`` so quotas count down.

Authentication: a single shared service token in the
``XOUT_USAGE_TOKEN`` env var maps to user-service's
``USAGE_INGEST_TOKEN``. The active-users pull and traffic report use
the same header (``X-Service-Token``).

Env (read on each tick so changes take effect without restart):
  USER_SERVICE_BASE_URL   — e.g. https://user.develop.cc
  XOUT_NODE_NAME          — e.g. us01 (matches nodes.name)
  XOUT_USAGE_TOKEN        — same as user-service USAGE_INGEST_TOKEN
  XRAY_API_ADDR           — default 127.0.0.1:10085
  XRAY_BIN                — default /usr/local/bin/xray
  USER_SYNC_INTERVAL      — seconds, default 30
  TRAFFIC_REPORT_INTERVAL — seconds, default 60
  PRESET_FILE             — default /data/preset.json
"""
from __future__ import annotations

import json
import logging
import os
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

LOGGER = logging.getLogger("xout-user-agent")
logging.basicConfig(
  format="%(asctime)s %(levelname)s xout-user-agent %(message)s",
  level=logging.INFO,
)


def env(name: str, default: str | None = None) -> str | None:
  v = os.getenv(name)
  return v if v else default


def http_json(method: str, url: str, *, headers: dict | None = None,
               body: dict | None = None, timeout: float = 15) -> tuple[int, Any]:
  req = urllib.request.Request(url, method=method, headers=headers or {})
  if body is not None:
    req.add_header("Content-Type", "application/json")
    req.data = json.dumps(body).encode("utf-8")
  try:
    with urllib.request.urlopen(req, timeout=timeout) as resp:
      raw = resp.read()
      try:
        return resp.status, json.loads(raw or b"null")
      except Exception:
        return resp.status, raw
  except urllib.error.HTTPError as e:
    raw = e.read()
    try:
      return e.code, json.loads(raw or b"null")
    except Exception:
      return e.code, raw


# ----- preset.json mutation -----


def load_preset(path: Path) -> list[dict]:
  if not path.exists():
    return []
  try:
    return json.loads(path.read_text("utf-8"))
  except Exception:
    LOGGER.exception("preset parse failed")
    return []


def update_preset_users(preset: list[dict], users: list[dict]) -> list[dict]:
  """For every vless inbound in ``preset``, set ``users[]`` to the
  subset of ``users`` whose ``tags`` selector matches that inbound's
  tag. Tag ``"*"`` means all inbounds on this node.
  """
  out = []
  for ib in preset:
    if (ib.get("protocol") or "").lower() != "vless":
      out.append(ib)
      continue
    tag = ib.get("tag") or ""
    matched = []
    for u in users:
      utags = u.get("tags") or ["*"]
      if "*" in utags or tag in utags:
        matched.append({"name": u["user_id"], "uuid": u["vless_uuid"]})
    new_ib = dict(ib)
    new_ib["users"] = matched
    out.append(new_ib)
  return out


def preset_users_changed(old: list[dict], new: list[dict]) -> bool:
  """Compare *just* the user lists across vless inbounds; ignore other
  preset fields so admin edits to e.g. ports don't accidentally
  trigger an extra xray bounce here.

  Also include a count of total vless inbounds in the signature so
  the "all vless inbounds got removed" case still triggers a restart
  (otherwise old=new=empty list and we miss the change).
  """
  def vless_user_sig(p: list[dict]) -> tuple:
    sig = []
    count = 0
    for ib in p:
      if (ib.get("protocol") or "").lower() != "vless":
        continue
      count += 1
      users = sorted(
        (u.get("name", ""), u.get("uuid", ""))
        for u in (ib.get("users") or [])
      )
      sig.append((ib.get("tag") or "", tuple(users)))
    return (count, tuple(sorted(sig)))
  return vless_user_sig(old) != vless_user_sig(new)


def write_preset_atomically(path: Path, preset: list[dict]) -> None:
  tmp = path.with_suffix(".json.tmp")
  tmp.write_text(json.dumps(preset, indent=2, ensure_ascii=False), "utf-8")
  tmp.replace(path)
  try:
    os.chmod(path, 0o600)
  except Exception:
    pass


# ----- xray stats via the `xray api` CLI -----


def xray_stats(api_addr: str, xray_bin: str) -> dict[str, dict[str, int]]:
  """Return {email: {uplink, downlink}} from xray's StatsService.

  Uses the `xray api stats` subcommand which prints a stats blob; we
  parse it. Reset=true so the next tick gets only the new traffic.
  """
  try:
    res = subprocess.run(
      [xray_bin, "api", "statsquery", f"-server={api_addr}", "-reset",
       "-pattern=user>>>"],
      capture_output=True, timeout=15, text=True,
    )
  except Exception:
    LOGGER.exception("xray api statsquery failed")
    return {}
  if res.returncode != 0:
    LOGGER.warning("xray api statsquery non-zero rc=%s stderr=%s",
                   res.returncode, res.stderr.strip())
    return {}
  out: dict[str, dict[str, int]] = {}
  try:
    parsed = json.loads(res.stdout) if res.stdout.strip() else {}
  except Exception:
    LOGGER.exception("xray statsquery JSON parse failed; raw=%r", res.stdout[:300])
    return {}
  # Names look like "user>>>EMAIL>>>traffic>>>uplink" / "...downlink".
  for entry in (parsed.get("stat") or []):
    name = entry.get("name") or ""
    val = int(entry.get("value") or 0)
    parts = name.split(">>>")
    if len(parts) != 4 or parts[0] != "user" or parts[2] != "traffic":
      continue
    email, kind = parts[1], parts[3]
    bucket = out.setdefault(email, {"uplink": 0, "downlink": 0})
    if kind == "uplink":
      bucket["uplink"] = val
    elif kind == "downlink":
      bucket["downlink"] = val
  return out


# ----- main loops -----


def report_resolved_preset(base: str, token: str, node: str,
                             preset_resolved_path: Path) -> None:
  """Push reality keys from /data/preset.json.resolved up to user-service
  so /sub/{token} can build real VLESS URIs (the in-DB preset still
  has 'auto' placeholders). Best-effort — runs once at agent boot.
  """
  if not preset_resolved_path.exists():
    LOGGER.info("resolved preset not found at %s, skipping report-preset",
                 preset_resolved_path)
    return
  try:
    preset = json.loads(preset_resolved_path.read_text("utf-8"))
  except Exception:
    LOGGER.exception("could not parse resolved preset")
    return
  inbounds = []
  for ib in preset:
    proto = (ib.get("protocol") or "").lower()
    tag = ib.get("tag")
    port = ib.get("port")
    if not tag or not port:
      continue
    entry = {
      "tag": tag, "port": int(port), "protocol": proto,
      "outbound_kind": (ib.get("outbound") or {}).get("type"),
    }
    if proto == "vless":
      reality = ib.get("reality") or {}
      entry["sni"] = reality.get("sni") or ""
      entry["public_key"] = (reality.get("public_key")
                             or reality.get("pubkey") or "")
      entry["short_id"] = reality.get("short_id") or ""
    inbounds.append(entry)
  url = f"{base.rstrip('/')}/api/internal/xout/report-preset"
  status, payload = http_json("POST", url,
                                headers={"X-Service-Token": token},
                                body={"node_name": node, "inbounds": inbounds})
  if status != 200:
    LOGGER.warning("report-preset failed status=%s body=%s", status, payload)
  else:
    LOGGER.info("report-preset ok: %d inbounds reported", len(inbounds))


def fetch_active_users(base: str, token: str, node: str) -> list[dict]:
  url = f"{base.rstrip('/')}/api/internal/xout/active-users?node_name={node}"
  status, payload = http_json("GET", url, headers={"X-Service-Token": token})
  if status != 200 or not isinstance(payload, dict):
    LOGGER.warning("active-users fetch failed status=%s body=%s", status, payload)
    return []
  return payload.get("users") or []


_PENDING_TRAFFIC_FILE = Path("/data/xout-pending-traffic.json")


def _load_pending_traffic() -> list[dict]:
  if not _PENDING_TRAFFIC_FILE.exists():
    return []
  try:
    return json.loads(_PENDING_TRAFFIC_FILE.read_text("utf-8")) or []
  except Exception:
    LOGGER.exception("could not read pending traffic spool")
    return []


def _save_pending_traffic(samples: list[dict]) -> None:
  try:
    tmp = _PENDING_TRAFFIC_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(samples), "utf-8")
    tmp.replace(_PENDING_TRAFFIC_FILE)
  except Exception:
    LOGGER.exception("could not spool pending traffic")


def report_traffic(base: str, token: str, node: str,
                    samples: list[dict]) -> dict:
  """POST traffic samples. Failed posts get spooled to disk and
  retried on the next tick — without this, the xray ``-reset`` flag
  in stats collection would cause permanent counter loss whenever
  user-service is unreachable.
  """
  pending = _load_pending_traffic()
  combined = pending + samples
  if not combined:
    return {}
  url = f"{base.rstrip('/')}/api/internal/xout/report-traffic"
  status, payload = http_json("POST", url,
                                headers={"X-Service-Token": token},
                                body={"node_name": node, "samples": combined})
  if status != 200:
    LOGGER.warning("report-traffic failed status=%s body=%s — spooling %d sample(s)",
                   status, payload, len(combined))
    _save_pending_traffic(combined)
    return {}
  # Success — clear the spool.
  if pending:
    LOGGER.info("flushed %d previously-spooled sample(s)", len(pending))
  if _PENDING_TRAFFIC_FILE.exists():
    try: _PENDING_TRAFFIC_FILE.unlink()
    except Exception: pass
  return payload if isinstance(payload, dict) else {}


def kill_xray() -> None:
  """Trigger an xray restart by killing PID 1. Compose's
  restart=unless-stopped will bring it back, picking up the new
  preset.json on entrypoint re-run.
  """
  LOGGER.info("preset users changed — restarting container to reload xray")
  try:
    os.kill(1, signal.SIGTERM)
  except Exception:
    LOGGER.exception("could not signal PID 1 — exiting agent so supervisor restarts us")
    sys.exit(0)


def map_users_by_email(users: list[dict]) -> dict[str, dict]:
  """Map xray-side ``email`` (which we set to user_id) back to the
  full row carrying product_code etc. — needed when we receive stats
  keyed by email."""
  return {u["user_id"]: u for u in users if u.get("user_id")}


def run() -> int:
  base = env("USER_SERVICE_BASE_URL")
  token = env("XOUT_USAGE_TOKEN")
  node = env("XOUT_NODE_NAME") or env("HOSTNAME")
  preset_path = Path(env("PRESET_FILE", "/data/preset.json") or "/data/preset.json")
  api_addr = env("XRAY_API_ADDR", "127.0.0.1:10085")
  xray_bin = env("XRAY_BIN", "/usr/local/bin/xray")
  sync_iv = int(env("USER_SYNC_INTERVAL", "30") or "30")
  traffic_iv = int(env("TRAFFIC_REPORT_INTERVAL", "60") or "60")
  if not base or not token or not node:
    LOGGER.error("missing config — need USER_SERVICE_BASE_URL, XOUT_USAGE_TOKEN, XOUT_NODE_NAME")
    return 2
  LOGGER.info("starting agent node=%s base=%s sync=%ss traffic=%ss",
               node, base, sync_iv, traffic_iv)

  # One-shot at boot: push the resolved preset (reality keys) up so
  # the subscription URL builder doesn't render with "auto" placeholders.
  report_resolved_preset(base, token, node,
                          preset_path.with_suffix(".json.resolved"))

  last_sync = 0.0
  last_traffic = 0.0
  last_users: list[dict] = []
  while True:
    now = time.time()
    if now - last_sync >= sync_iv:
      try:
        users = fetch_active_users(base, token, node)
        if users != last_users:
          preset = load_preset(preset_path)
          new_preset = update_preset_users(preset, users)
          if preset_users_changed(preset, new_preset):
            write_preset_atomically(preset_path, new_preset)
            last_users = users
            kill_xray()
            return 0
          else:
            LOGGER.debug("user list semantically unchanged")
        last_users = users
      except Exception:
        LOGGER.exception("user-sync tick failed")
      last_sync = now
    if now - last_traffic >= traffic_iv:
      try:
        stats = xray_stats(api_addr, xray_bin)
        # email is the user_id. Build samples by joining with last_users
        # so we know product_code per user.
        by_id = map_users_by_email(last_users)
        samples = []
        for email, traf in stats.items():
          u = by_id.get(email)
          if u is None:
            continue
          samples.append({
            "user_id": email,
            "product_code": u["product_code"],
            "uplink_bytes": traf.get("uplink", 0),
            "downlink_bytes": traf.get("downlink", 0),
          })
        if samples:
          report_traffic(base, token, node, samples)
      except Exception:
        LOGGER.exception("traffic-report tick failed")
      last_traffic = now
    time.sleep(1)


if __name__ == "__main__":
  sys.exit(run())
