# Sidecar agents

a2agw can serve an agent written in any language (spec section 7.7). The gateway speaks A2A to
callers on the agent's behalf and hands each turn to the agent through a small local
contract, the invoke protocol `a2agw.invoke/1`. This page is that contract. The agent is reached
over HTTP (the webhook transport) or runs as a process the gateway supervises (the stdio
transport); both carry the same invoke body and events.

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
| `Accept-Encoding` | `identity` (send the body uncompressed) |
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
| Cannot connect, the address is refused by the tier, or the request fails before a response | `agent unreachable` |
| Connection breaks mid-response | `agent connection lost` |
| Invalid JSON, invalid event, wrong content type, an undecodable body, a limit exceeded | `agent protocol error` |
| The gateway could not prepare the consult grant | `agent consult setup failed` |
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

## Stdio transport

The agent is a long-lived local process that the gateway starts and supervises. It reads
JSON lines on stdin and writes JSON lines on stdout. Configure it in `a2agw.yaml`:

```yaml
agents:
  - id: coder
    name: Coder
    description: Writes and reviews code
    skills:
      - {id: code, name: Code, description: Writes code, tags: [dev]}
    durable_sessions: false
    stdio:
      command: [node, agent.js]   # argv, at least one item; no shell
      cwd: agents/coder           # optional; relative to the config file's directory
      env_from:                   # optional: variable for the process -> gateway env var
        OPENAI_API_KEY: CODER_OPENAI_KEY
      max_concurrency: 16         # optional: turns in flight at once
      timeout_s: 300              # optional: end-to-end deadline per turn
```

An entry has exactly one transport (`webhook` or `stdio`). Environment values are never
written inline: `env:` is rejected, use `env_from`. A variable named in `env_from` that is not
set in the gateway's environment is a configuration error naming it. In Python, the same agent
is `AgentSpec(..., adapter=StdioAdapter(["node", "agent.js"], cwd=..., env={...}))`; the
host starts the process at startup and stops it at shutdown.

The process does not inherit the gateway's environment. It gets only `PATH`, `HOME`, `LANG`,
`TZ` and `PYTHONPATH` (those that are set), plus the `env_from` variables.

### Framing

One JSON object per line, UTF-8, each ending with `\n`. Every turn is a run with its own id
(32 hex characters); runs are multiplexed over the one process, so several can be in flight
at once and their events may interleave.

The gateway writes to stdin:

| Line | Meaning |
|---|---|
| `{"op":"invoke","id":"<run id>","request":{...}}` | Start a run. `request` is the invoke body, exactly as the webhook's request body |
| `{"op":"cancel","id":"<run id>"}` | Stop the run: the task was cancelled, timed out, or the run broke the protocol |
| `{"op":"shutdown"}` | Exit cleanly; stdin is closed right after |

The agent writes to stdout, for each event of a run:

```json
{"id": "<run id>", "event": {"type": "text", "text": "fn main() {"}}
```

`event` is one of the webhook's events (same types, fields and rules). A run ends at its
first `need_input`, `need_auth`, `done`, `failed` or `reply`; the gateway ignores anything
after it for that run. Unlike a webhook response, there is no "end of stream": always end a
run with a terminal event, or it fails when its deadline passes.

Stdout carries the protocol only: write logs to stderr. The gateway forwards stderr to the
logger `a2agw.agent.<agent id>` at INFO, one record per line, capped at 4 KiB a line.

A minimal agent in Python:

```python
import json, sys

for raw in sys.stdin:
    op = json.loads(raw)
    if op["op"] == "shutdown":
        break
    if op["op"] == "invoke":
        out = {"id": op["id"], "event": {"type": "done", "text": "echo: " + op["request"]["text"]}}
        sys.stdout.write(json.dumps(out) + "\n")
        sys.stdout.flush()
```

### Supervision

- The process starts with the host (or on the first turn). The gateway never uses a shell.
- When it exits, every run in flight fails with `agent process exited`, and the gateway starts
  it again after a back-off of 1, 2, 4 ... up to 30 seconds. The back-off starts again at 1
  second once a process has stayed up for 60 seconds.
- A turn that arrives while the process is down waits for it, up to the turn's deadline, then
  fails with `agent unavailable`.
- At shutdown the gateway sends `shutdown` and closes stdin, waits 5 seconds, sends SIGTERM,
  waits 2 more seconds, then kills the process.

### Failures

As for the webhook transport, the A2A caller sees a fixed reason and the gateway logs the
detail (an error class or a protocol rule, never a value) at WARNING on
`a2agw.agent.<agent id>`.

| Situation | Task fails with |
|---|---|
| The process exited (or was stopped) during the run | `agent process exited` |
| No running process within the deadline (it cannot start, or is backing off) | `agent unavailable` |
| An invalid event, a line without exactly `id` and `event`, a limit exceeded | `agent protocol error` |
| The gateway could not prepare the consult grant | `agent consult setup failed` |
| `timeout_s` passed (including a wait for a free slot under `max_concurrency`) | `agent timed out` |

A line that breaks the protocol fails only the run it names, and that run is sent `cancel`. A
line that names no run (invalid JSON, no `id`, longer than 1 MiB) is logged and ignored: the
run it was meant for then ends at its deadline. Lines for a run that has ended are ignored.

### Limits

The webhook limits apply to each run: 1 MiB a line (`MAX_LINE_BYTES`), 16 MiB of lines in
all (`MAX_RESPONSE_BYTES`) and 10,000 events (`MAX_EVENTS`).
