"""Cross-service flows over the real services, every response checked against openapi/."""

from __future__ import annotations

import pytest
from estate import conforms, new_product, stock


def place(orders, *lines):
    return orders.post("/orders", json={"lines": [{"sku": s, "qty": q} for s, q in lines]})


@pytest.mark.parametrize("name", ["orders", "inventory"])
def test_openapi_documents_are_well_formed(name):
    import estate

    api = estate.load_api(name)
    assert api["openapi"].startswith("3.")
    for path, item in api["paths"].items():
        for method, op in item.items():
            if method == "parameters":
                continue
            assert op.get("responses"), f"{method} {path} documents no responses"

    def walk(node):  # every $ref resolves
        if isinstance(node, dict):
            if "$ref" in node:
                estate.resolve(api, node)
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(api)


def test_health(orders, inventory, orders_api, inventory_api):
    conforms(orders_api, "GET", "/healthz", orders.get("/healthz"))
    conforms(inventory_api, "GET", "/healthz", inventory.get("/healthz"))


def test_catalogue_conforms(inventory, inventory_api):
    body = conforms(inventory_api, "GET", "/products", inventory.get("/products"))
    assert {"WIDGET-1", "GADGET-2", "GIZMO-3"} <= {p["sku"] for p in body["products"]}
    conforms(inventory_api, "GET", "/products/{sku}", inventory.get("/products/WIDGET-1"))
    conforms(inventory_api, "GET", "/products/{sku}", inventory.get("/products/NOPE"))


def test_placing_an_order_reserves_inventory(orders, inventory, orders_api):
    sku = new_product(inventory, stock=10)
    res = place(orders, (sku, 4))
    assert res.status_code == 201, res.text
    order = conforms(orders_api, "POST", "/orders", res)
    assert order["status"] == "placed"
    assert order["lines"] == [{"sku": sku, "qty": 4}]
    assert stock(inventory, sku) == 6
    got = conforms(orders_api, "GET", "/orders/{order_id}", orders.get(f"/orders/{order['id']}"))
    assert got == order
    listed = conforms(orders_api, "GET", "/orders", orders.get("/orders"))
    assert order["id"] in [o["id"] for o in listed["orders"]]


def test_insufficient_stock_is_refused_by_both(orders, inventory, orders_api, inventory_api):
    sku = new_product(inventory, stock=2)
    direct = inventory.post(f"/products/{sku}/reserve", json={"qty": 3})
    assert direct.status_code == 409
    conforms(inventory_api, "POST", "/products/{sku}/reserve", direct)
    res = place(orders, (sku, 3))
    assert res.status_code == 409
    assert conforms(orders_api, "POST", "/orders", res)["sku"] == sku
    assert stock(inventory, sku) == 2


def test_unknown_product_is_422(orders, orders_api):
    res = place(orders, ("NO-SUCH-SKU", 1))
    assert res.status_code == 422
    assert conforms(orders_api, "POST", "/orders", res)["error"] == "unknown product"


def test_cancel_flow(orders, inventory, orders_api):
    sku = new_product(inventory, stock=5)
    order = place(orders, (sku, 1)).json()
    res = orders.post(f"/orders/{order['id']}/cancel")
    assert conforms(orders_api, "POST", "/orders/{order_id}/cancel", res)["status"] == "cancelled"
    again = orders.post(f"/orders/{order['id']}/cancel")
    assert again.status_code == 409
    conforms(orders_api, "POST", "/orders/{order_id}/cancel", again)


def test_reserve_and_release_conform(inventory, inventory_api):
    sku = new_product(inventory, stock=3)
    r = inventory.post(f"/products/{sku}/reserve", json={"qty": 2})
    assert conforms(inventory_api, "POST", "/products/{sku}/reserve", r) == {"sku": sku, "stock": 1}
    r = inventory.post(f"/products/{sku}/release", json={"qty": 2})
    assert conforms(inventory_api, "POST", "/products/{sku}/release", r) == {"sku": sku, "stock": 3}
