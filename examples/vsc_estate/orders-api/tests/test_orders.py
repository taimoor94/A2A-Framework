def place(client, *lines):
    return client.post("/orders", json={"lines": [{"sku": s, "qty": q} for s, q in lines]})


def test_healthz(client):
    assert client.get("/healthz").json() == {"ok": True}


def test_place_order_reserves_stock(client, inventory):
    res = place(client, ("WIDGET-1", 3))
    assert res.status_code == 201
    order = res.json()
    assert order["status"] == "placed"
    assert order["lines"] == [{"sku": "WIDGET-1", "qty": 3}]
    assert inventory.stock("WIDGET-1") == 17


def test_get_and_list_orders(client):
    first = place(client, ("WIDGET-1", 1)).json()
    second = place(client, ("GADGET-2", 2)).json()
    assert client.get(f"/orders/{first['id']}").json() == first
    assert [o["id"] for o in client.get("/orders").json()["orders"]] == [first["id"], second["id"]]


def test_unknown_order_is_404(client):
    assert client.get("/orders/999").status_code == 404
    assert client.get("/orders/abc").status_code == 404
    assert client.post("/orders/999/cancel").status_code == 404


def test_insufficient_stock_is_409(client, inventory):
    res = place(client, ("GIZMO-3", 1))
    assert res.status_code == 409
    assert res.json() == {"error": "insufficient stock", "sku": "GIZMO-3"}
    assert client.get("/orders").json()["orders"] == []


def test_unknown_product_is_422(client):
    res = place(client, ("NOPE-9", 1))
    assert res.status_code == 422
    assert res.json()["error"] == "unknown product"


def test_invalid_bodies_are_400(client):
    for body in (
        {},
        {"lines": []},
        {"lines": [{"sku": "WIDGET-1", "qty": 0}]},
        {"lines": [{"sku": "WIDGET-1", "qty": True}]},
        {"lines": [{"qty": 1}]},
    ):
        assert client.post("/orders", json=body).status_code == 400, body
    assert client.post("/orders", content=b"{").status_code == 400


def test_cancel_order(client):
    order = place(client, ("WIDGET-1", 2)).json()
    res = client.post(f"/orders/{order['id']}/cancel")
    assert res.status_code == 200
    assert res.json()["status"] == "cancelled"
    again = client.post(f"/orders/{order['id']}/cancel")
    assert again.status_code == 409


def test_inventory_down_is_502(tmp_path):
    import httpx
    from app import create_app
    from starlette.testclient import TestClient

    def down(request):
        raise httpx.ConnectError("refused", request=request)

    app = create_app(str(tmp_path / "o.db"), "http://x", transport=httpx.MockTransport(down))
    with TestClient(app) as c:
        assert place(c, ("WIDGET-1", 1)).status_code == 502
