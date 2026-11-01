"""orders-api: customer orders, stored in SQLite. Each order line reserves stock in the
inventory service over HTTP. The HTTP contract is ``openapi/orders.yaml`` in the contract
repository.

    GET  /healthz              readiness probe
    GET  /orders               every order, oldest first
    POST /orders               place an order {"lines": [{"sku": ..., "qty": ...}]}
    GET  /orders/{id}          one order
    POST /orders/{id}/cancel   cancel an order

Run it with ``python app.py``. Environment: ``PORT`` (default 8000), ``HOST`` (default
127.0.0.1), ``ORDERS_DB`` (default ``orders.db``), ``INVENTORY_URL`` (default
``http://127.0.0.1:8001``).
"""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Iterator
from contextlib import asynccontextmanager, closing, contextmanager
from typing import Any
from urllib.parse import quote

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

SCHEMA = """
CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE TABLE IF NOT EXISTS order_lines (
    order_id INTEGER NOT NULL REFERENCES orders (id),
    line_no INTEGER NOT NULL,
    sku TEXT NOT NULL,
    qty INTEGER NOT NULL,
    PRIMARY KEY (order_id, line_no)
);
"""


class InventoryError(Exception):
    """The inventory service refused a call or could not be reached."""

    def __init__(self, status: int, body: dict[str, Any]) -> None:
        super().__init__(body.get("error", "inventory error"))
        self.status = status
        self.body = body


class InventoryClient:
    def __init__(self, base_url: str, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._http = httpx.AsyncClient(base_url=base_url, transport=transport, timeout=5.0)

    async def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        try:
            res = await self._http.post(path, json=body)
        except httpx.HTTPError:
            raise InventoryError(502, {"error": "inventory unavailable"}) from None
        data = res.json() if res.content else {}
        if res.status_code != 200:
            raise InventoryError(res.status_code, data)
        return data

    async def reserve(self, sku: str, qty: int) -> dict[str, Any]:
        return await self._post(f"/products/{quote(sku, safe='')}/reserve", {"qty": qty})

    async def aclose(self) -> None:
        await self._http.aclose()


class Store:
    def __init__(self, path: str) -> None:
        self.path = path
        with self.connect() as db:
            db.executescript(SCHEMA)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        with closing(sqlite3.connect(self.path)) as db:
            db.row_factory = sqlite3.Row
            with db:  # one transaction
                yield db

    def create(self, lines: list[dict[str, Any]]) -> int:
        with self.connect() as db:
            order_id = db.execute("INSERT INTO orders (status) VALUES ('placed')").lastrowid
            db.executemany(
                "INSERT INTO order_lines (order_id, line_no, sku, qty) VALUES (?, ?, ?, ?)",
                [(order_id, n, line["sku"], line["qty"]) for n, line in enumerate(lines)],
            )
        assert order_id is not None
        return order_id

    def _order(self, db: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
        lines = db.execute(
            "SELECT sku, qty FROM order_lines WHERE order_id = ? ORDER BY line_no", (row["id"],)
        ).fetchall()
        return {
            "id": row["id"],
            "status": row["status"],
            "created_at": row["created_at"],
            "lines": [dict(line) for line in lines],
        }

    def get(self, order_id: int) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
            return None if row is None else self._order(db, row)

    def all(self) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute("SELECT * FROM orders ORDER BY id").fetchall()
            return [self._order(db, row) for row in rows]

    def set_status(self, order_id: int, status: str) -> None:
        with self.connect() as db:
            db.execute("UPDATE orders SET status = ? WHERE id = ?", (status, order_id))


def error(status: int, message: str, **extra: Any) -> JSONResponse:
    return JSONResponse({"error": message, **extra}, status_code=status)


def parse_lines(body: Any) -> list[dict[str, Any]] | None:
    lines = body.get("lines") if isinstance(body, dict) else None
    if not isinstance(lines, list) or not lines:
        return None
    for line in lines:
        if not isinstance(line, dict) or not isinstance(line.get("sku"), str):
            return None
        qty = line.get("qty")
        if not isinstance(qty, int) or isinstance(qty, bool) or qty <= 0:
            return None
    return [{"sku": line["sku"], "qty": line["qty"]} for line in lines]


def create_app(
    db_path: str, inventory_url: str, *, transport: httpx.AsyncBaseTransport | None = None
) -> Starlette:
    store = Store(db_path)
    inventory = InventoryClient(inventory_url, transport)

    async def healthz(request: Request) -> JSONResponse:
        return JSONResponse({"ok": True})

    async def list_orders(request: Request) -> JSONResponse:
        return JSONResponse({"orders": store.all()})

    async def create_order(request: Request) -> JSONResponse:
        try:
            body = await request.json()
        except ValueError:
            return error(400, "body must be JSON")
        lines = parse_lines(body)
        if lines is None:
            return error(400, "lines must be a non-empty list of {sku, qty > 0}")
        for line in lines:
            try:
                await inventory.reserve(line["sku"], line["qty"])
            except InventoryError as e:
                if e.status == 404:
                    return error(422, "unknown product", sku=line["sku"])
                if e.status == 409:
                    return error(409, "insufficient stock", sku=line["sku"])
                return error(502, "inventory unavailable")
        order_id = store.create(lines)
        return JSONResponse(store.get(order_id), status_code=201)

    def find(request: Request) -> dict[str, Any] | None:
        try:
            return store.get(int(request.path_params["order_id"]))
        except ValueError:
            return None

    async def get_order(request: Request) -> JSONResponse:
        order = find(request)
        return JSONResponse(order) if order else error(404, "order not found")

    async def cancel_order(request: Request) -> JSONResponse:
        order = find(request)
        if order is None:
            return error(404, "order not found")
        if order["status"] == "cancelled":
            return error(409, "order already cancelled")
        store.set_status(order["id"], "cancelled")
        return JSONResponse(store.get(order["id"]))

    @asynccontextmanager
    async def lifespan(app: Starlette) -> Any:
        yield
        await inventory.aclose()

    return Starlette(
        routes=[
            Route("/healthz", healthz),
            Route("/orders", list_orders, methods=["GET"]),
            Route("/orders", create_order, methods=["POST"]),
            Route("/orders/{order_id}", get_order, methods=["GET"]),
            Route("/orders/{order_id}/cancel", cancel_order, methods=["POST"]),
        ],
        lifespan=lifespan,
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        create_app(
            os.environ.get("ORDERS_DB", "orders.db"),
            os.environ.get("INVENTORY_URL", "http://127.0.0.1:8001"),
        ),
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "8000")),
        log_level="warning",
    )
