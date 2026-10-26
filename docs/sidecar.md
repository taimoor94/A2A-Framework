# Sidecar agents

a2agw can serve an agent written in any language (spec section 7.7). The gateway speaks A2A to
callers on the agent's behalf and hands each turn to the agent through a small local
contract, the invoke protocol `a2agw.invoke/1`. This page is that contract.

## Webhook transport

The agent is an HTTP endpoint (conventionally `POST /a2agw/invoke`). Configure it in
`a2agw.yaml`:

```yaml
agents:
  - id: coder                     # [a-z0-9][a-z0-9-]{0,62}
    name: Coder
    description: Writes and reviews code
    skills:
      - {id: code, name: Code, description: Writes code, tags: [dev]}
    input_modes: [text/plain]     # optional; default text/plain + application/json
    output_modes: [text/plain]    # optional
    durable_sessions: false       # true: input-required tasks survive a gateway restart
    webhook:
      url: http://127.0.0.1:9000/a2agw/invoke
      secret_env: CODER_SECRET    # optional: env var holding the signing secret
      timeout_s: 300              # optional: end-to-end deadline per turn
      tier: internal              # optional: netguard tier the URL is vetted with
```

An entry has exactly one transport. A secret is never written inline: `secret:` is rejected,
use `secret_env`. In Python, the same agent is
`AgentSpec(..., adapter=WebhookAdapter(url, secret=..., timeout_s=..., tier=...))`.

The URL is vetted at connect time with its tier. On `internal` (the default) plain `http` to
loopback and private addresses is allowed; other tiers need `https` and a public address.
Cloud metadata addresses (`169.254.169.254` and friends) are refused on every tier. Redirects
are never followed.

### Request

One `POST` per turn (a new message, or the reply to an `input-required` question).

Headers:

| Header | Value |
|---|---|
| `Content-Type` | `application/json` |
| `Accept` | `application/x-ndjson, application/json` |
| `X-A2AGW-Protocol` | `a2agw.invoke/1` |
| `X-A2AGW-Timestamp` | Unix time in seconds, when the request was signed |
| `X-A2AGW-Signature` | `v1=<hex>`, only when a secret is configured |

Body:

```json
{
  "protocol": "a2agw.invoke/1",
  "agent_id": "coder",
  "task_id": "…",
  "context_id": "…",
  "resumed": false,
  "text": "write fizzbuzz in rust",
  "parts": [{"text": "write fizzbuzz in rust"}],
  "metadata": {},
  "caller": {"id": "key:alice", "kind": "api_key"},
  "consult": null,
  "deadline": 1793000000.5
}
```

- `text` is the text parts joined with newlines; `parts` are the A2A 1.0 `Part` objects in
  their JSON form (text, url, raw or data, with `mediaType`, `filename` and `metadata`).
- `resumed` is true when the turn answers a question the agent asked (`need_input`).
  `context_id` stays the same across the turns of one conversation.
- `caller` is the authenticated caller (`kind` is `api_key`, `jwt` or `anonymous`), or null.
  The caller's credentials and scopes are never sent.
- `consult` is a grant to consult partner agents through the gateway for this turn
  (`{url, token, expires_at}`), or null.
- `deadline` is when the gateway gives up on the turn (epoch seconds), or null.

### Response

Answer with a 2xx status and one of:

- `application/x-ndjson`: one JSON event per line, streamed as the agent works. This is the
  way to report progress and stream text.
- `application/json`: `{"text": "..."}` completes the task with that text, or
  `{"events": [ ... ]}` carries the same events as the stream, all at once.

Events:

| `type` | Fields | Meaning |
|---|---|---|
| `status` | `text` | A progress message (task stays `working`) |
| `text` | `text` | A piece of the answer; pieces are appended to one streamed artifact named `output` |
| `artifact` | `parts`, `name?`, `artifact_id?`, `append?` (false), `last?` (true) | An artifact chunk; `parts` are A2A `Part` objects in JSON |
| `usage` | `tokens_in`, `tokens_out`, `cost` | Token and cost accounting, summed into the task's metadata |
| `need_input` | `question` | Ask the caller; the task becomes `input-required` |
| `need_auth` | `scheme`, `detail?` | The task becomes `auth-required` |
| `done` | `text?` | Complete the task (`text` becomes a `result` artifact) |
| `failed` | `error` | Fail the task with this reason |
| `reply` | `text` | Answer with a message (a direct reply when the agent allows one) |

`need_input`, `need_auth`, `done`, `failed` and `reply` end the turn; the gateway stops
reading and closes the connection. A stream that ends cleanly without one of them completes
the task. Blank lines are ignored. Unknown event types, unknown or missing fields and wrong
field types are protocol errors.

### Failures

What the A2A caller sees as the failure reason. The agent's response body is never passed on;
the gateway logs the detail (an error class, status code or protocol rule, never a value) at
WARNING on the logger `a2agw.agent.<agent id>`.

| Situation | Task fails with |
|---|---|
| Non-2xx status | `agent returned HTTP <code>` |
| Cannot connect, or the address is refused by the tier | `agent unreachable` |
| Connection breaks mid-response | `agent connection lost` |
| Invalid JSON, invalid event, wrong content type, a limit exceeded | `agent protocol error` |
| `timeout_s` passed (connect to last event) | `agent timed out` |

### Limits

| Limit | Value |
|---|---|
| One NDJSON line (without its newline) | 1 MiB (`MAX_LINE_BYTES`) |
| The whole response body | 16 MiB (`MAX_RESPONSE_BYTES`) |
| Events in one response | 10,000 (`MAX_EVENTS`) |

### Cancellation

When the A2A task is cancelled, the gateway closes the connection. That is the cancel signal:
stop work for the turn when your server sees the client disconnect (for example a write that
fails, or your framework's disconnect notification). Nothing is sent afterwards; there is no
separate cancel request.

### Verifying the signature

With a secret configured, verify every request before acting on it. The signature is HMAC-SHA256
over the timestamp, a dot, and the raw body bytes exactly as received:

```text
ts        = header "X-A2AGW-Timestamp"
sig       = header "X-A2AGW-Signature"
if abs(now() - int(ts)) > 300:            reject 401   # replayed or stale
expected  = "v1=" + hex(hmac_sha256(key = secret, msg = ts + "." + raw_body))
if not constant_time_equal(sig, expected): reject 401
body      = json_parse(raw_body)
if body.protocol != "a2agw.invoke/1":      reject 400
```

Parse the body only after the check, and compare in constant time. Keep the endpoint on a
loopback or private address; the signature proves the request came from your gateway.
