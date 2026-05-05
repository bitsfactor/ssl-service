from __future__ import annotations
import os
import uvicorn

if __name__ == "__main__":
  uvicorn.run(
    "app.main:app",
    host="0.0.0.0",
    port=int(os.getenv("PORT", "8200")),
    log_level=os.getenv("LOG_LEVEL", "info"),
  )
