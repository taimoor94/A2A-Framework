"""Test fixtures: the app on a temporary database, talking to an in-memory fake of the
inventory service through ``httpx.MockTransport`` (no network)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import httpx
import pytest
from app import create_app
from starlette.testclient import TestClient


@dataclass
class FakeInventory:
    """The inventory HTTP API (``openapi/inventory.yaml``) over a dict, recording every call."""

    products: dict[str, dict[str, Any]] = field(default_factory=dict)
    requests: list[httpx.Request] = field(default_factory=list)

    def add(self, sku: str, stock: int, price_cents: int = 1000) -> None:
        self.products[sku] = {
            "sku": sku,
            "name": sku.title(),
            "stock": stock,
            "price_cents": price_cents,
        }

    def stock(self, sku: str) -> int:
        return self.products[sku]["stock"]

    def calls(self, action: str) -> list[tuple[str, dict[str, Any]]]:
        """(sku, body) of every POST /products/<sku>/<action>."""
        out = []
        for req in self.requests:
            parts = req.url.path.strip("/").split("/")
            if req.method == "POST" and len(parts) == 3 and parts[2] == action:
                out.append((parts[1], json.loads(req.content or b"{}")))
        return out

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        parts = request.url.path.strip("/").split("/")
        if parts[0] != "products":
            return httpx.Response(404, json={"error": "not found"})
        if len(parts) == 1 and request.method == "GET":
            return httpx.Response(200, json={"products": list(self.products.values())})
        product = self.products.get(parts[1]) if len(parts) > 1 else None
        if product is None:
            return httpx.Response(404, json={"error": "unknown product", "sku": parts[1]})
        if len(parts) == 2 and request.method == "GET":
            return httpx.Response(200, json=product)
        if len(parts) == 3 and request.method == "POST":
            qty = json.loads(request.content or b"{}").get("qty")
            if not isinstance(qty, int) or qty <= 0:
                return httpx.Response(400, json={"error": "qty must be a positive integer"})
            if parts[2] == "reserve":
                if product["stock"] < qty:
                    return httpx.Response(
                        409,
                        json={
                            "error": "insufficient stock",
                            "sku": product["sku"],
                            "available": product["stock"],
                        },
                    )
                product["stock"] -= qty
                return httpx.Response(200, json={"sku": product["sku"], "stock": product["stock"]})
            if parts[2] == "release":
                product["stock"] += qty
                return httpx.Response(200, json={"sku": product["sku"], "stock": product["stock"]})
        return httpx.Response(404, json={"error": "not found"})


@pytest.fixture
def inventory() -> FakeInventory:
    fake = FakeInventory()
    fake.add("WIDGET-1", stock=20, price_cents=1250)
    fake.add("GADGET-2", stock=5, price_cents=4999)
    fake.add("GIZMO-3", stock=0, price_cents=799)
    return fake


@pytest.fixture
def client(tmp_path, inventory):
    app = create_app(
        str(tmp_path / "orders.db"),
        "http://inventory.test",
        transport=httpx.MockTransport(inventory.handle),
    )
    with TestClient(app) as c:
        yield c
