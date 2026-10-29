// The Node coder: an a2agw webhook agent (invoke protocol a2agw.invoke/1), Node 24 standard
// library only. See README.md next to this file and docs/sidecar.md.
//
//   POST /a2agw/invoke   one turn: verify the signature, stream NDJSON events
//   GET  /healthz        readiness probe
//
// Environment:
//   PORT        port to listen on (default 9000; 0 picks a free one)
//   HOST        address to listen on (default 127.0.0.1)
//   SECRET_ENV  name of the variable holding the signing secret (default CODER_SECRET); the
//               gateway's webhook `secret_env` names the same secret
//
// On start it prints one line to stdout, {"listening": <port>}. Logs go to stderr, and never
// include the secret or a consult token.
import { createHmac, timingSafeEqual } from "node:crypto";
import { createServer, request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";

const PROTOCOL = "a2agw.invoke/1";
const MAX_SKEW_S = 300;
const MAX_BODY_BYTES = 1024 * 1024;
const CONSULT_WAIT_S = 30;
const PARTNER = "security";

const secretEnv = process.env.SECRET_ENV || "CODER_SECRET";
const secret = process.env[secretEnv];
if (!secret) {
  console.error(`coder: ${secretEnv} is not set; refusing to start without a signing secret`);
  process.exit(2);
}

const log = (msg) => console.error(`coder: ${msg}`);

// -- signature ---------------------------------------------------------------------------

function verified(headers, raw) {
  const ts = headers["x-a2agw-timestamp"];
  const sig = headers["x-a2agw-signature"];
  if (typeof ts !== "string" || typeof sig !== "string" || !/^\d{1,12}$/.test(ts)) {
    return false;
  }
  if (Math.abs(Date.now() / 1000 - Number(ts)) > MAX_SKEW_S) {
    return false; // replayed or stale
  }
  const mac = createHmac("sha256", secret);
  mac.update(`${ts}.`);
  mac.update(raw);
  const expected = Buffer.from(`v1=${mac.digest("hex")}`);
  const given = Buffer.from(sig);
  return given.length === expected.length && timingSafeEqual(given, expected);
}

// -- consulting a partner through the gateway ----------------------------------------------

function consult(grant, partner, message, signal) {
  const url = new URL(`${grant.url}/partners/${encodeURIComponent(partner)}/messages`);
  const body = JSON.stringify({ message, wait_seconds: CONSULT_WAIT_S });
  const send = url.protocol === "https:" ? httpsRequest : httpRequest;
  return new Promise((resolve, reject) => {
    const req = send(
      url,
      {
        method: "POST",
        signal,
        headers: {
          // The turn's consult token: kept in memory, never logged.
          authorization: `Bearer ${grant.token}`,
          "content-type": "application/json",
          "content-length": Buffer.byteLength(body),
        },
      },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          if (res.statusCode !== 200) {
            reject(new Error(`gateway answered HTTP ${res.statusCode}`));
            return;
          }
          try {
            resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
          } catch {
            reject(new Error("gateway answered invalid JSON"));
          }
        });
        res.on("error", reject);
      },
    );
    req.on("error", reject);
    req.end(body);
  });
}

// -- the agent ----------------------------------------------------------------------------

function draft(text) {
  const goal = text.split("\n", 1)[0].slice(0, 200);
  return [
    `// node coder: ${goal}\n`,
    'import { createServer } from "node:http";\n\n',
    "const todos = new Map();\n",
    "createServer((req, res) => {\n",
    '  if (req.url === "/todos" && req.method === "GET") {\n',
    '    res.writeHead(200, { "content-type": "application/json" });\n',
    "    return res.end(JSON.stringify([...todos.values()]));\n",
    "  }\n",
    "  res.writeHead(404).end();\n",
    "}).listen(8080);\n",
  ];
}

async function turn(invoke, emit, signal) {
  emit({ type: "status", text: "drafting code" });
  const code = draft(invoke.text);
  let review = "no review (no consult grant)";
  if (invoke.consult) {
    emit({ type: "status", text: `asking ${PARTNER} for a review` });
    try {
      const answer = await consult(
        invoke.consult,
        PARTNER,
        `Review this code for security issues:\n${code.join("")}`,
        signal,
      );
      // Partner text is untrusted data from a third party: quoted, never acted on.
      review =
        answer.state === "completed"
          ? `${PARTNER} (${answer.state}): ${String(answer.text || "").slice(0, 500)}`
          : `${PARTNER} (${answer.state}): ${answer.reason || "no answer"}`;
      log(`turn ${invoke.task_id}: ${PARTNER} answered ${answer.state}`);
    } catch (e) {
      if (signal.aborted) return;
      // The code is still useful without the review: say so instead of failing the turn.
      review = `${PARTNER} review unavailable`;
      log(`turn ${invoke.task_id}: consulting ${PARTNER} failed (${e.message})`);
    }
  }
  if (signal.aborted) return;
  // Two text events: the gateway appends them to one streamed "output" artifact.
  emit({ type: "text", text: code.join("") });
  emit({ type: "text", text: `// review: ${review}` });
  emit({ type: "done" });
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > MAX_BODY_BYTES) {
        reject(Object.assign(new Error("body too large"), { status: 413 }));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function refuse(res, status, error) {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify({ error }));
}

async function invokeRoute(req, res) {
  let raw;
  try {
    raw = await readBody(req);
  } catch (e) {
    if (!res.headersSent && !res.destroyed) refuse(res, e.status || 400, "bad request");
    return;
  }
  if (!verified(req.headers, raw)) {
    log("rejected a request: bad signature or timestamp");
    refuse(res, 401, "unauthenticated");
    return;
  }
  let invoke;
  try {
    invoke = JSON.parse(raw.toString("utf8"));
  } catch {
    refuse(res, 400, "invalid JSON");
    return;
  }
  if (invoke?.protocol !== PROTOCOL) {
    refuse(res, 400, "unsupported protocol");
    return;
  }

  // The gateway closing the connection is the cancel signal.
  const controller = new AbortController();
  res.on("close", () => {
    if (!res.writableFinished) {
      controller.abort();
      log(`turn ${invoke.task_id}: cancelled (client disconnected)`);
    }
  });
  res.writeHead(200, { "content-type": "application/x-ndjson", "cache-control": "no-store" });
  const emit = (event) => {
    if (!controller.signal.aborted) res.write(`${JSON.stringify(event)}\n`);
  };
  log(`turn ${invoke.task_id}: started`);
  try {
    await turn(invoke, emit, controller.signal);
    if (!controller.signal.aborted) log(`turn ${invoke.task_id}: done`);
  } catch (e) {
    if (controller.signal.aborted) return;
    log(`turn ${invoke.task_id}: failed (${e.message})`);
    emit({ type: "failed", error: "coder could not finish the turn" });
  } finally {
    if (!res.destroyed) res.end();
  }
}

const server = createServer((req, res) => {
  if (req.method === "GET" && req.url === "/healthz") {
    res.writeHead(200, { "content-type": "text/plain" }).end("ok");
    return;
  }
  if (req.url === "/a2agw/invoke") {
    if (req.method !== "POST") {
      res.writeHead(405, { allow: "POST" }).end();
      return;
    }
    invokeRoute(req, res).catch((e) => {
      log(`internal error (${e.name})`);
      if (!res.headersSent) refuse(res, 500, "internal error");
      else res.destroy();
    });
    return;
  }
  res.writeHead(404).end();
});

const shutdown = () => server.close(() => process.exit(0));
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);

server.listen(Number(process.env.PORT ?? 9000), process.env.HOST || "127.0.0.1", () => {
  process.stdout.write(`${JSON.stringify({ listening: server.address().port })}\n`);
});
