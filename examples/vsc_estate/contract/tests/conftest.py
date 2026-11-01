"""Fixtures: one running estate (inventory-service + orders-api) shared by the whole session."""

from __future__ import annotations

import os
from types import SimpleNamespace

import estate
import httpx
import pytest


@pytest.fixture(scope="session")
def services(tmp_path_factory):
    for env_name, path, marker in (
        ("VSC_WS_ORDERS_API", estate.ORDERS_REPO, "app.py"),
        ("VSC_WS_INVENTORY_SERVICE", estate.INVENTORY_REPO, "server.mjs"),
    ):
        if not (path / marker).is_file():
            if os.environ.get(env_name):
                pytest.fail(f"{env_name}={path} has no {marker}")
            pytest.skip(f"service repository not found at {path} (set {env_name})")
    tmp = tmp_path_factory.mktemp("estate")
    inventory = estate.start_inventory(tmp)
    try:
        orders = estate.start_orders(tmp, inventory.url)
    except BaseException:
        inventory.stop()
        raise
    try:
        yield SimpleNamespace(inventory=inventory, orders=orders, tmp=tmp)
    finally:
        orders.stop()
        inventory.stop()


@pytest.fixture
def inventory(services):
    with httpx.Client(base_url=services.inventory.url, timeout=10.0) as c:
        yield c


@pytest.fixture
def orders(services):
    with httpx.Client(base_url=services.orders.url, timeout=10.0) as c:
        yield c


@pytest.fixture(scope="session")
def inventory_api():
    return estate.load_api("inventory")


@pytest.fixture(scope="session")
def orders_api():
    return estate.load_api("orders")
