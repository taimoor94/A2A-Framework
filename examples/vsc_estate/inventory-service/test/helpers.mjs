// Shared by the test files: a fresh server on a free port per test file.
import { after, before } from "node:test";

import { start } from "../server.mjs";

export function useServer(seed) {
  const ctx = { url: "" };
  let server;
  before(async () => {
    server = await start({ port: 0, seed });
    ctx.url = `http://127.0.0.1:${server.address().port}`;
  });
  after(() => new Promise((resolve) => server.close(resolve)));
  return ctx;
}

export async function call(ctx, method, path, body, headers = {}) {
  const res = await fetch(ctx.url + path, {
    method,
    headers: body === undefined ? headers : { "content-type": "application/json", ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  return { status: res.status, headers: res.headers, body: text ? JSON.parse(text) : null };
}
