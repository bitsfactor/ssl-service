"""Tiny stdlib HTTP server with a /health endpoint.

Doubles as: a minimal example of a deployable service, AND something
the platform's healthcheck logic can verify against on a live node.
"""
from __future__ import annotations

import json
import os
import signal
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime, timezone


PORT = int(os.environ.get("PORT", "8080"))
LOG_LEVEL = os.environ.get("LOG_LEVEL", "info")
DATABASE_URL = os.environ.get("DATABASE_URL", "")
JWT_SECRET = os.environ.get("JWT_SECRET", "")


class Handler(BaseHTTPRequestHandler):
  def _send(self, status: int, body: dict) -> None:
    payload = json.dumps(body).encode("utf-8")
    self.send_response(status)
    self.send_header("Content-Type", "application/json; charset=utf-8")
    self.send_header("Content-Length", str(len(payload)))
    self.end_headers()
    self.wfile.write(payload)

  def do_GET(self) -> None:  # noqa: N802
    if self.path == "/health":
      self._send(200, {
        "status": "ok",
        "now": datetime.now(timezone.utc).isoformat(),
        "have_database_url": bool(DATABASE_URL),
        "have_jwt_secret": bool(JWT_SECRET),
      })
    elif self.path == "/":
      self._send(200, {
        "service": "service-template",
        "log_level": LOG_LEVEL,
      })
    else:
      self._send(404, {"error": "not found"})

  def log_message(self, format, *args):  # noqa: A003
    sys.stdout.write("%s - - [%s] %s\n" % (
      self.address_string(),
      self.log_date_time_string(),
      format % args,
    ))


def main() -> None:
  print(f"Starting service-template on :{PORT} (log_level={LOG_LEVEL})", flush=True)
  server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
  signal.signal(signal.SIGTERM, lambda *_: server.shutdown())
  signal.signal(signal.SIGINT, lambda *_: server.shutdown())
  thread = threading.Thread(target=server.serve_forever, daemon=True)
  thread.start()
  thread.join()


if __name__ == "__main__":
  main()
