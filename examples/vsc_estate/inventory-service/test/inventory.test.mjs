import assert from "node:assert/strict";
import { test } from "node:test";

import { call, useServer } from "./helpers.mjs";

const ctx = useServer([
  { sku: "A-1", name: "Apple", stock: 10, price_cents: 100 },
  { sku: "B-2", name: "Banana", stock: 1, price_cents: 50 },
]);

test("healthz", async () => {
  const res = await call(ctx, "GET", "/healthz");
  assert.equal(res.status, 200);
  assert.deepEqual(res.body, { ok: true });
});

test("lists the seed products", async () => {
  const res = await call(ctx, "GET", "/products");
  assert.equal(res.status, 200);
  assert.deepEqual(
    res.body.products.map((p) => p.sku),
    ["A-1", "B-2"],
  );
});

test("gets one product, 404 for an unknown one", async () => {
  const one = await call(ctx, "GET", "/products/A-1");
  assert.equal(one.status, 200);
  assert.equal(one.body.price_cents, 100);
  const none = await call(ctx, "GET", "/products/NOPE");
  assert.equal(none.status, 404);
  assert.equal(none.body.error, "unknown product");
});

test("creates a product and refuses a duplicate or invalid one", async () => {
  const p = { sku: "C-3", name: "Cherry", stock: 3, price_cents: 20 };
  assert.equal((await call(ctx, "POST", "/products", p)).status, 201);
  assert.equal((await call(ctx, "POST", "/products", p)).status, 409);
  const bad = await call(ctx, "POST", "/products", { ...p, sku: "x y", stock: -1 });
  assert.equal(bad.status, 400);
});

test("reserves and releases stock", async () => {
  const r = await call(ctx, "POST", "/products/A-1/reserve", { qty: 4 });
  assert.equal(r.status, 200);
  assert.deepEqual(r.body, { sku: "A-1", stock: 6 });
  const back = await call(ctx, "POST", "/products/A-1/release", { qty: 4 });
  assert.deepEqual(back.body, { sku: "A-1", stock: 10 });
});

test("refuses to reserve more than the stock", async () => {
  const r = await call(ctx, "POST", "/products/B-2/reserve", { qty: 2 });
  assert.equal(r.status, 409);
  assert.equal(r.body.error, "insufficient stock");
  assert.equal(r.body.available, 1);
  assert.equal((await call(ctx, "GET", "/products/B-2")).body.stock, 1);
});

test("rejects a bad qty or body", async () => {
  for (const qty of [0, -1, 1.5, "2"]) {
    assert.equal((await call(ctx, "POST", "/products/A-1/reserve", { qty })).status, 400);
  }
  const res = await fetch(`${ctx.url}/products/A-1/reserve`, { method: "POST", body: "[" });
  assert.equal(res.status, 400);
});

test("deletes a product", async () => {
  await call(ctx, "POST", "/products", { sku: "D-4", name: "Date", stock: 1, price_cents: 1 });
  assert.equal((await call(ctx, "DELETE", "/products/D-4")).status, 204);
  assert.equal((await call(ctx, "GET", "/products/D-4")).status, 404);
});

test("unknown routes are 404", async () => {
  assert.equal((await call(ctx, "GET", "/nope")).status, 404);
  assert.equal((await call(ctx, "PATCH", "/products/A-1")).status, 404);
});
