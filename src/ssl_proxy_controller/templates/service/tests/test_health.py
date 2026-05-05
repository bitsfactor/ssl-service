"""Smoke test: /health responds, /product/info returns the manifest."""
from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app


def test_health() -> None:
  client = TestClient(app)
  response = client.get("/health")
  assert response.status_code == 200
  assert response.json() == {"status": "ok"}


def test_product_info_shape() -> None:
  client = TestClient(app)
  response = client.get("/product/info")
  assert response.status_code == 200
  body = response.json()
  # The manifest may be empty in the smoke environment (no .product.yaml
  # alongside the rendered package), but it must be a dict.
  assert isinstance(body, dict)
