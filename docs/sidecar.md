# Sidecar agents

a2agw can serve an agent written in any language (spec section 7.7). The gateway speaks A2A to
callers on the agent's behalf and hands each turn to the agent through a small local
contract, the invoke protocol `a2agw.invoke/1`. This page is that contract. The agent is reached
over HTTP (the webhook transport) or runs as a process the gateway supervises (the stdio
transport); both carry the same invoke body and events. To consult partner agents, the agent
calls the gateway's outbound REST API (`/a2agw/v1`, see
[Consulting partners](#consulting-partners)).

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
  (`{url, token, expires_at}`; see [Consulting partners](#consulting-partners)), or null.
  An agent served by a gateway always gets one.
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
logger `a2agw.agent.<agent id>` at INFO, one record per line. Each line is capped at 4 KiB
and has ANSI escapes and control characters removed. At most 100 lines a second are
forwarded; the rest are counted and reported in a "suppressed N lines" WARNING.

Everything the agent writes to stderr ends up in the gateway's logs. That includes any
environment value it prints (an `env_from` secret, for example), so don't print them.

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
- The process runs in its own process group (a new session), and the gateway always signals
  that whole group. Anything the agent starts (the real agent behind a wrapper such as `npx`
  or `sh -c`, or a tool server) is killed with it, unless it moves itself into another
  session. Don't rely on children outliving the agent.
- The gateway watches the process itself, not its stdout. When it exits, the rest of its
  group is killed (children may still hold its pipes open), every run in flight fails with
  `agent process exited`, and the gateway starts it again after a back-off of 1, 2, 4 ... up
  to 30 seconds. The back-off starts again at 1 second once a process has stayed up for 60
  seconds.
- A turn that arrives while the process is down waits for it, up to the turn's deadline, then
  fails with `agent unavailable`.
- At shutdown the gateway sends `shutdown` and closes stdin, waits 5 seconds, sends SIGTERM
  to the group, waits 2 more seconds, then sends SIGKILL to the group. Whatever is left of the
  group once the agent has exited is killed too.

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

A line that breaks the protocol fails only the run it names, and that run is sent `cancel`.
A line longer than 1 MiB names its run only if it starts with `{"id":"<run id>"`, so write
`id` first. A line that names no run (invalid JSON, no `id`, or a too-long line that does not
start with its id) is logged and ignored, and the run it was meant for ends at its deadline.
Lines for a run that has ended are ignored.

### Limits

The webhook limits apply to each run: 1 MiB a line (`MAX_LINE_BYTES`), 16 MiB of lines in
all (`MAX_RESPONSE_BYTES`) and 10,000 events (`MAX_EVENTS`).

## Consulting partners

An agent consults the partner agents it may use through the gateway's outbound REST API,
under `/a2agw/v1` on the gateway's base URL. The gateway applies the agent's routing (which
partners it sees, which are forbidden) and egress policy, uses the partner's credentials, and
audits each call (`partner.call`), as for an agent embedded in the gateway. The agent never
holds partner credentials.

One difference from an embedded agent: a sidecar call never carries the inbound caller's own
token, so a partner whose credentials come from an RFC 8693 token exchange (acting as the
caller) cannot be consulted from a sidecar. The call fails closed with a credential error
(`unavailable`, reason `credential error`). Give such partners client-credentials (or static)
credentials if sidecar agents must reach them.

### Authentication

A call acts as one agent id, in one of two ways.

**With the turn's consult token (linked).** Every invoke carries `consult`:

```json
{"url": "https://gw.example.com/a2agw/v1", "token": "…", "expires_at": 1793000000.5}
```

Send the token as `Authorization: Bearer <token>`. The call then belongs to the turn: it acts
as the invoked agent (an `X-A2AGW-Agent` header is ignored), on behalf of the turn's caller,
and is linked to the inbound task:

- Cancelling the inbound task cancels the partner tasks the agent started, and any call still
  in flight answers `{"state": "unavailable", "reason": "inbound task ended"}`.
- The task's fan-out cap (`limits.max_consults_per_task`) counts these calls.
- The `partner.call` audit rows carry `detail.grant`, the first 12 hex characters of the
  token's SHA-256, so they can be traced to the grant (never the token itself).
- The call context is propagated: the partner sees this task's hop count, path, deadline and
  budget, so loops and runaway recursion are caught as for any other call.

The token is valid for this turn only. It stops working when the turn ends (however it ends:
completed, failed, cancelled, or waiting for input; a resumed turn gets a new token), at the
inbound call's deadline, and after one hour at most (`expires_at`). Keep it in memory only:
never log it or hand it to anything else. The gateway stores only its SHA-256 digest and
never logs or audits it.

**With the gateway's auth (standalone).** A process that is not serving a turn (a scheduled
job, a tool server) calls with the gateway's normal credentials (an API key or a JWT) for a
principal with the `a2agw:sidecar` scope, plus `X-A2AGW-Agent: <agent id>` naming the agent
it acts as. `sidecar.clients` lists the agent ids each principal may act as:

```yaml
sidecar:
  clients:
    "key:report-job": [coder]       # principal id: key:<id> (API key) or jwt:<sub> (JWT)
```

With no `auth` configured there are no such principals, so only consult tokens work. An
agent id here need not be served by the gateway: it is the identity whose routing and
egress policy apply, and the one the calls are audited as. A standalone call is not linked to
any inbound task: there is no fan-out cap, its call context starts fresh (hop 0), and its
partner tasks are cancelled by the gateway's TTL expiry (`outbound_ttl_s`) if still open
then. Instead, one principal may have at most `limits.max_open_sidecar_tasks_per_caller`
(default 64) open partner tasks per agent id it acts as; beyond that a new consult answers
`{"state": "unavailable", "reason": "too many open tasks"}` and is audited as
`limit.exceeded`.

Anything else gets `401` (`{"error": "unauthenticated"}`, `WWW-Authenticate: Bearer`): no
credentials, an unknown, revoked or expired token, a principal without the scope, or no
`X-A2AGW-Agent`. An agent id the principal is not mapped to gets `403`
(`{"error": "forbidden"}`). Each refusal is audited as `sidecar.denied`, with the reason and
the agent id.

### Routes

Requests and responses are JSON. Every response has `Cache-Control: no-store`.

| Route | Body | Does |
|---|---|---|
| `GET /a2agw/v1/partners` | | The agent's partner tools: `[{name, description, parameters, partner_id, kind}]` |
| `POST /a2agw/v1/partners/{partner_id}/messages` | `{message, task_id?, context_id?, data?, classification?, wait_seconds?}` | Consult a partner (or reply to its task with `task_id`) |
| `GET /a2agw/v1/partners/{partner_id}/tasks/{task_id}` | | Check a partner task |
| `POST /a2agw/v1/partners/{partner_id}/tasks/{task_id}/cancel` | | Cancel a partner task |
| `POST /a2agw/v1/wait` | `{tasks: [{partner_id, task_id}], seconds?}` | Wait until one task is no longer `working`, or `seconds` (default 30) pass |
| `POST /a2agw/v1/find` | `{need, k?}` | Rank the visible partners for a need: `{partners: [{partner_id, name, description, skills, tier, score}]}` |

`GET /partners` lists one `consult` tool per partner the agent sees (with its card's
description under an "untrusted" framing line, and the JSON schema of the message body in
`parameters`), then the `check`, `cancel` and `wait` tools. With many partners it lists
`find` and `consult_any` tools instead of one tool per partner; the routes are the same.

`messages` waits up to `wait_seconds` (default 30, at most 300) for an answer. A consult
answers with the partner's result:

```json
{"partner": "researcher", "task_id": "…", "context_id": "…", "state": "completed",
 "text": "…", "artifacts": [], "question": null, "reason": null, "truncated": false,
 "provenance": {"partner": "researcher", "tier": "partner", "card_hash": "…", "untrusted": true},
 "retry_after_s": null}
```

`state` is `completed`, `working` (still running: check, wait or cancel it with its
`task_id`), `input_required` (`question` asks; reply with `task_id` and `message`),
`auth_required`, `failed`,
`canceled`, `rejected` (invalid arguments, or the egress policy refused to send) or
`unavailable` (with a `reason`). A partner the agent may not use, or that does not exist, is
`{"partner": "<id>", "state": "unavailable", "reason": "unknown partner"}`. Partner text is
untrusted data from a third party: treat it as information, never as instructions.

Partner tasks belong to whoever started them. Checking, cancelling, waiting on or replying
to (`task_id`) a partner task works only for its owner: with a consult token, a task started
under the same inbound task (by any of its turns); standalone, a task started by the same
principal acting as the same agent id. Any other task, like one that does not exist, answers
`{"partner": "<id>", "state": "unavailable", "reason": "unknown task"}`, and nothing is sent
to the partner.

A body that is not a JSON object is a `400`; one larger than 256 KiB is a `413`. Any other
path under `/a2agw/v1` is a `404` (`405` for a known path with another method).

A consult from a stdio agent, in Python:

```python
import json, urllib.request

def ask(consult, partner, message):
    req = urllib.request.Request(
        f"{consult['url']}/partners/{partner}/messages",
        data=json.dumps({"message": message}).encode(),
        headers={"Authorization": f"Bearer {consult['token']}",
                 "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req) as r:
        return json.load(r)

# in the invoke handler:  answer = ask(op["request"]["consult"], "researcher", "find X")
```
