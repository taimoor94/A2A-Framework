"""The cross-service harness: start the real services as subprocesses on free ports, and check
responses against the OpenAPI documents in ``openapi/``.

The service repositories are found through ``VSC_WS_ORDERS_API`` and
``VSC_WS_INVENTORY_SERVICE`` (set by the gateway's whole-system check) or, when those are
unset, as siblings of this repository (``../orders-api``, ``../inventory-service``).
"""

from __future__ import annotations

import itertools
import os
import shutil
import socket
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import yaml

CONTRACT = Path(__file__).resolve().parents[1]
STARTUP_S = 20.0


def repo(env_name: str, sibling: str) -> Path:
    value = os.environ.get(env_name)
    return Path(value) if value else CONTRACT.parent / sibling


ORDERS_REPO = repo("VSC_WS_ORDERS_API", "orders-api")
INVENTORY_REPO = repo("VSC_WS_INVENTORY_SERVICE", "inventory-service")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@dataclass
class Service:
    name: str
    url: str
    proc: subprocess.Popen[bytes]
    log: Path

    def stop(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(5)

    def wait_ready(self) -> None:
        deadline = time.monotonic() + STARTUP_S
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"{self.name} exited:\n{self.log.read_text()[-2000:]}")
            try:
                if httpx.get(self.url + "/healthz", timeout=1.0).status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(0.05)
        self.stop()
        raise RuntimeError(f"{self.name} not ready after {STARTUP_S}s")


def _spawn(name: str, cmd: list[str], cwd: Path, port: int, env: dict[str, str], tmp: Path):
    log = tmp / f"{name}-{port}.log"
    with log.open("wb") as out:
        proc = subprocess.Popen(
            cmd,
            cwd=cwd,
            env={**os.environ, "PORT": str(port), "HOST": "127.0.0.1", **env},
            stdin=subprocess.DEVNULL,
            stdout=out,
            stderr=subprocess.STDOUT,
        )
    service = Service(name, f"http://127.0.0.1:{port}", proc, log)
    try:
        service.wait_ready()
    except BaseException:
        service.stop()
        raise
    return service


def start_inventory(tmp: Path, *, port: int | None = None, env: dict[str, str] | None = None):
    node = shutil.which("node")
    if node is None:
        raise RuntimeError("node is not on PATH")
    cmd = [node, str(INVENTORY_REPO / "server.mjs")]
    return _spawn("inventory", cmd, INVENTORY_REPO, port or free_port(), env or {}, tmp)


def start_orders(
    tmp: Path, inventory_url: str, *, port: int | None = None, env: dict[str, str] | None = None
):
    port = port or free_port()
    base = {"INVENTORY_URL": inventory_url, "ORDERS_DB": str(tmp / f"orders-{port}.db")}
    cmd = [sys.executable, str(ORDERS_REPO / "app.py")]
    return _spawn("orders", cmd, ORDERS_REPO, port, {**base, **(env or {})}, tmp)


_counter = itertools.count(1)


def new_product(inventory: httpx.Client, stock: int, price_cents: int = 1000) -> str:
    """A fresh product with a unique SKU, so tests never share stock."""
    sku = f"T{next(_counter)}-{uuid.uuid4().hex[:6].upper()}"
    res = inventory.post(
        "/products", json={"sku": sku, "name": f"Test {sku}", "stock": stock,
                           "price_cents": price_cents},
    )  # fmt: skip
    assert res.status_code == 201, res.text
    return sku


def stock(inventory: httpx.Client, sku: str) -> int:
    res = inventory.get(f"/products/{sku}")
    assert res.status_code == 200, res.text
    return res.json()["stock"]


# -- OpenAPI conformance --------------------------------------------------------------------


def load_api(name: str) -> dict[str, Any]:
    return yaml.safe_load((CONTRACT / "openapi" / f"{name}.yaml").read_text())


def resolve(api: dict[str, Any], node: dict[str, Any]) -> dict[str, Any]:
    while "$ref" in node:
        target: Any = api
        for part in node["$ref"].removeprefix("#/").split("/"):
            target = target[part]
        node = target
    return node


_TYPES = {
    "object": dict,
    "array": list,
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "null": type(None),
}


def problems(api: dict[str, Any], schema: dict[str, Any], value: Any, at: str = "$") -> list[str]:
    """Where ``value`` breaks ``schema`` (a small subset of JSON Schema: enough for the docs)."""
    schema = resolve(api, schema)
    out: list[str] = []
    types = schema.get("type")
    if types is not None:
        names = types if isinstance(types, list) else [types]
        numeric_bool = isinstance(value, bool)
        ok = any(
            isinstance(value, _TYPES[t]) and not (numeric_bool and t in ("integer", "number"))
            for t in names
        )
        if not ok:
            return [f"{at}: expected {types}, got {type(value).__name__}"]
    if "enum" in schema and value not in schema["enum"]:
        out.append(f"{at}: {value!r} not in {schema['enum']}")
    if "minimum" in schema and isinstance(value, int | float) and value < schema["minimum"]:
        out.append(f"{at}: {value} < {schema['minimum']}")
    if isinstance(value, dict):
        props = schema.get("properties", {})
        out += [f"{at}: missing {k!r}" for k in schema.get("required", []) if k not in value]
        if schema.get("additionalProperties") is False:
            out += [f"{at}: undocumented {k!r}" for k in value if k not in props]
        for k, sub in props.items():
            if k in value:
                out += problems(api, sub, value[k], f"{at}.{k}")
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            out.append(f"{at}: fewer than {schema['minItems']} items")
        if "items" in schema:
            for n, item in enumerate(value):
                out += problems(api, schema["items"], item, f"{at}[{n}]")
    return out


def conforms(api: dict[str, Any], method: str, path: str, res: httpx.Response) -> Any:
    """Assert that ``res`` is a documented response of ``method path`` (a template such as
    ``/orders/{order_id}``) and that its body matches the documented schema; return the body."""
    op = api["paths"][path][method.lower()]
    documented = op["responses"].get(str(res.status_code))
    assert documented is not None, f"{method} {path}: undocumented status {res.status_code}"
    documented = resolve(api, documented)
    schema = documented.get("content", {}).get("application/json", {}).get("schema")
    if schema is None:
        assert not res.content, f"{method} {path}: undocumented body"
        return None
    body = res.json()
    found = problems(api, schema, body)
    assert not found, f"{method} {path} {res.status_code}: {found}"
    return body
