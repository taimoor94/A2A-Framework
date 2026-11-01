// inventory-service: the product catalogue and its stock. Node 24 standard library only.
// The HTTP contract is ../contract/openapi/inventory.yaml (in the contract repository).
//
//   GET    /healthz                    readiness probe
//   GET    /products                   every product
//   POST   /products                   add a product {sku, name, stock, price_cents}
//   GET    /products/:sku              one product
//   DELETE /products/:sku              remove a product
//   POST   /products/:sku/reserve      take {qty} units out of stock (409 when short)
//   POST   /products/:sku/release      put {qty} units back
//
// Environment (when run as a program):
//   PORT  port to listen on (default 8001; 0 picks a free one)
//   HOST  address to listen on (default 127.0.0.1)
//
// On start it prints one line to stdout, {"listening": <port>}. State is in memory: a restart
// goes back to the seed catalogue.
import { createServer } from "node:http";
import { pathToFileURL } from "node:url";

const MAX_BODY_BYTES = 64 * 1024;
const SKU = /^[A-Z0-9][A-Z0-9-]{0,39}$/;

export const SEED = [
  { sku: "WIDGET-1", name: "Widget", stock: 20, price_cents: 1250 },
  { sku: "GADGET-2", name: "Gadget", stock: 5, price_cents: 4999 },
  { sku: "GIZMO-3", name: "Gizmo", stock: 0, price_cents: 799 },
];

class HttpError extends Error {
  constructor(status, message, extra = {}) {
    super(message);
    this.status = status;
    this.body = { error: message, ...extra };
  }
}

const isCount = (v) => Number.isInteger(v) && v >= 0;
const isQty = (v) => Number.isInteger(v) && v > 0;

function send(res, status, body) {
  if (body === undefined) {
    res.writeHead(status).end();
    return;
  }
  const data = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(data),
  });
  res.end(data);
}

async function readJson(req) {
  let size = 0;
  const chunks = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) throw new HttpError(413, "body too large");
    chunks.push(chunk);
  }
  try {
    const body = JSON.parse(Buffer.concat(chunks).toString("utf8") || "null");
    if (body === null || typeof body !== "object" || Array.isArray(body)) throw new Error();
    return body;
  } catch {
    throw new HttpError(400, "body must be a JSON object");
  }
}

export function createInventory(seed = SEED) {
  const products = new Map(seed.map((p) => [p.sku, { ...p }]));

  function find(sku) {
    const product = products.get(sku);
    if (!product) throw new HttpError(404, "unknown product", { sku });
    return product;
  }

  function qtyOf(body) {
    if (!isQty(body.qty)) throw new HttpError(400, "qty must be a positive integer");
    return body.qty;
  }

  const routes = {
    "GET /healthz": () => [200, { ok: true }],
    "GET /products": () => [200, { products: [...products.values()] }],
    "POST /products": (_, body) => {
      const { sku, name, stock, price_cents } = body;
      if (typeof sku !== "string" || !SKU.test(sku)) throw new HttpError(400, "invalid sku");
      if (typeof name !== "string" || !name) throw new HttpError(400, "invalid name");
      if (!isCount(stock)) throw new HttpError(400, "stock must be a non-negative integer");
      if (!isCount(price_cents)) {
        throw new HttpError(400, "price_cents must be a non-negative integer");
      }
      if (products.has(sku)) throw new HttpError(409, "product exists", { sku });
      const product = { sku, name, stock, price_cents };
      products.set(sku, product);
      return [201, product];
    },
    "GET /products/:sku": (sku) => [200, find(sku)],
    "DELETE /products/:sku": (sku) => {
      find(sku);
      products.delete(sku);
      return [204, undefined];
    },
    "POST /products/:sku/reserve": (sku, body) => {
      const product = find(sku);
      const qty = qtyOf(body);
      if (product.stock < qty) {
        throw new HttpError(409, "insufficient stock", { sku, available: product.stock });
      }
      product.stock -= qty;
      return [200, { sku, stock: product.stock }];
    },
    "POST /products/:sku/release": (sku, body) => {
      const product = find(sku);
      product.stock += qtyOf(body);
      return [200, { sku, stock: product.stock }];
    },
  };

  async function handle(req, res) {
    const url = new URL(req.url, "http://inventory");
    const parts = url.pathname.split("/").filter(Boolean);
    let key = `${req.method} ${url.pathname}`;
    let sku = null;
    if (parts[0] === "products" && parts.length >= 2 && parts.length <= 3) {
      sku = decodeURIComponent(parts[1]);
      key = `${req.method} /products/:sku${parts[2] ? `/${parts[2]}` : ""}`;
    }
    const route = routes[key];
    if (!route) throw new HttpError(404, "not found");
    const body = req.method === "POST" ? await readJson(req) : {};
    const [status, out] = route(sku, body, url);
    send(res, status, out);
  }

  return { products, handle };
}

export function start({ port = 0, host = "127.0.0.1", seed = SEED } = {}) {
  const inventory = createInventory(seed);
  const server = createServer((req, res) => {
    inventory.handle(req, res).catch((err) => {
      if (err instanceof HttpError) {
        send(res, err.status, err.body);
      } else {
        console.error(`inventory: ${err.stack || err}`);
        send(res, 500, { error: "internal error" });
      }
    });
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => resolve(server));
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const server = await start({
    port: Number(process.env.PORT ?? 8001),
    host: process.env.HOST || "127.0.0.1",
  });
  console.log(JSON.stringify({ listening: server.address().port }));
  const stop = () => server.close(() => process.exit(0));
  process.on("SIGTERM", stop);
  process.on("SIGINT", stop);
}
