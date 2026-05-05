"""HTTP surface for {{name}}.

This is where you add endpoints. The three handlers below (`/`, `/health`,
`/product/info`) are required by the platform — don't remove them.
Everything else is yours.
"""
from __future__ import annotations

from pathlib import Path

import yaml
from fastapi import FastAPI, Request

from .product_adapter import get_user, report_usage


app = FastAPI(title="{{display_name}}")


# Cached at import time — `.product.yaml` doesn't change at runtime.
def _load_product_manifest() -> dict:
  here = Path(__file__).resolve().parent.parent
  candidate = here / ".product.yaml"
  if not candidate.exists():
    return {}
  try:
    return yaml.safe_load(candidate.read_text(encoding="utf-8")) or {}
  except yaml.YAMLError:
    return {}


_PRODUCT_MANIFEST = _load_product_manifest()


@app.get("/")
def root(request: Request) -> dict:
  user = get_user(request)
  return {"service": "{{name}}", "user": user.id}


@app.get("/health")
def health() -> dict:
  return {"status": "ok"}


@app.get("/product/info")
def product_info() -> dict:
  """The platform's catalog calls this to verify the live manifest."""
  return _PRODUCT_MANIFEST.get("product", {}) or {}


# ---- example endpoint ------------------------------------------------------
# Keep / replace as you like. Demonstrates the user + billing pattern.

@app.get("/example")
def example(request: Request) -> dict:
  user = get_user(request)
  report_usage("{{name}}.example.call", user_id=user.id)
  return {"hello": user.id, "plan": user.plan}
