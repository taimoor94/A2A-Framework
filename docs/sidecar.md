# Sidecar agents

a2agw can serve an agent written in any language (spec section 7.7). The gateway speaks A2A to
callers on the agent's behalf and hands each turn to the agent through a small local
contract, the invoke protocol `a2agw.invoke/1`. This page is that contract. The agent is reached
over HTTP (the webhook transport) or runs as a process the gateway supervises (the stdio
transport); both carry the same invoke body and events. To consult partner agents, the agent
calls the gateway's outbound REST API (`/a2agw/v1`, see
[Consulting partners](#consulting-partners)). MCP-capable agents can use the same partner
tools through the gateway's [MCP server](#mcp-server).

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

The same check in Node (standard library), from
[`examples/node_coder/agent.mjs`](../examples/node_coder/agent.mjs):

```js
import { createHmac, timingSafeEqual } from "node:crypto";

function verified(headers, raw /* Buffer, as received */) {
  const ts = headers["x-a2agw-timestamp"];
  const sig = headers["x-a2agw-signature"];
  if (typeof ts !== "string" || typeof sig !== "string" || !/^\d{1,12}$/.test(ts)) return false;
  if (Math.abs(Date.now() / 1000 - Number(ts)) > 300) return false;
  const mac = createHmac("sha256", secret).update(`${ts}.`).update(raw).digest("hex");
  const expected = Buffer.from(`v1=${mac}`);
  const given = Buffer.from(sig);
  return given.length === expected.length && timingSafeEqual(given, expected);
}
```

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
- The call continues the turn's trace: its `a2agw.partner_call` span is a child of the
  turn's `a2agw.inbound` span, though the request itself carries no trace context. The agent
  needs no tracing code for its partner calls to be in the caller's trace.

`url` is `base_url` + `/a2agw/v1` unless `sidecar.consult_url` is set
(`AgentHost(consult_url=...)`): use it when the agent reaches the gateway at another address,
for example `http://gateway:8000/a2agw/v1` on a container network while the cards advertise
`http://localhost:8000`. The gateway never fetches it; it only hands it to the agent.

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
`X-A2AGW-Agent` (a value that is not a valid agent id, lower-case letters, digits and `-`,
counts as none and is never audited). An agent id the principal is not mapped to gets `403`
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
Partner conversations too: a consult with `context_id` continues only a conversation whose
partner tasks the caller owns under the same rule (a partner that answered with a plain
message, no task, is recorded as the caller's conversation as well); any other, or one no
handle records, answers `{"partner": "<id>", "state": "unavailable", "reason": "unknown
context"}`, and nothing is sent. Embedded agents' partner tools follow the same rules
(`PartnerClient.owns` and `owns_context` are the predicates both paths use).

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

## MCP server

The same partner tools are also served over MCP, so an MCP-capable agent (Claude Code,
Cursor, the Claude Agent SDK, OpenAI Agents, ...) can consult the partner network with no code
of its own. Install the extra (`pip install 'a2a-gateway[mcp]'`) and list the agent ids to
serve:

```yaml
sidecar:
  clients:
    "key:claude-code": [coder]   # standalone callers, as for the REST API
  mcp:
    enabled: true                # mount /a2agw/mcp/{agent_id} on `a2agw serve`
    agents: [coder]              # the agent ids served over MCP (HTTP and stdio)
```

Each agent id is one MCP server. It has one tool per partner tool of `GET /a2agw/v1/partners`,
with the same names (`ask_<partner>`, or `find_partners` and `consult_partner`, plus
`a2a_check_task`, `a2a_cancel_task` and `a2a_wait`) and the same arguments. A tool's input
schema leaves out the gateway-only `x-` keys (such as the size limit on `data`); the gateway
still enforces them. Every description ends with a note that partner results are untrusted
data, and the server's instructions say the same.

A tool call does exactly what the matching REST call does: the same routing, egress policy,
audit, ownership of partner tasks, `unknown partner` and `unknown task` answers, and the same
limits. Its result has the JSON answer of the REST call twice: as text content and as
`structuredContent`. `isError` is set when the state is `failed` or `rejected`. A tool that is
not in the current list (a partner since quarantined, disabled, removed or forbidden) answers
`isError` with `{"state": "unavailable", "reason": "unknown tool"}`, and nothing is sent.
The list is recomputed on every `tools/list`, and when partners change the gateway sends
`notifications/tools/list_changed` to the open sessions (best effort).

### Streamable HTTP

`a2agw serve` serves each listed agent id at `/a2agw/mcp/{agent_id}`. Authentication is the
REST API's, and comes first: a caller that is not authenticated, or not allowed to act as the
agent id in the path, gets `401` or `403` whatever the id, and only an allowed caller learns
that an id is not served over MCP (`404`).

- **Consult token (linked).** A webhook or stdio agent can hand its turn's token to an MCP
  client as `Authorization: Bearer <token>`, on `{base_url}/a2agw/mcp/{agent_id}` for its own
  agent id (a token for another agent id is a `403`). The session's calls are linked to the
  inbound task, as described in [Authentication](#authentication), and the session itself
  ends when the token stops working (the turn ended).
- **Standalone.** The gateway's API key or JWT, for a principal with the `a2agw:sidecar`
  scope that `sidecar.clients` maps to the agent id. The path names the agent: no
  `X-A2AGW-Agent` header is needed.

Refusals are `401`/`403` and audited as `sidecar.denied`, as for the REST API; a path that
is not a valid agent id is a `401` (no agent id), and a consult token revoked while its
request was being set up is a `401` too. A session can only be used with the credentials
that opened it (another caller gets `404`, as for an unknown session). DNS-rebinding
protection accepts only requests whose `Host` (and `Origin`, when sent) is the host of
`base_url` or of `sidecar.consult_url` (the gateway as sidecar agents reach it); behind a
proxy, keep the original `Host`.

On an exit signal (SIGTERM, SIGINT) the gateway ends the open sessions at once, so the server
does not wait for their notification streams. An application that embeds the host and stops
uvicorn some other way (`server.should_exit = True`) should `await host.end_streams()` first.

Enabling MCP without the extra fails at startup with a message naming it
(`pip install 'a2a-gateway[mcp]'`).

Claude Code (`.mcp.json`, or `claude mcp add --transport http a2agw <url> --header ...`):

```json
{
  "mcpServers": {
    "a2agw": {
      "type": "http",
      "url": "https://gw.example.com/a2agw/mcp/coder",
      "headers": {"X-API-Key": "${A2AGW_API_KEY}"}
    }
  }
}
```

Cursor (`.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "a2agw": {
      "url": "https://gw.example.com/a2agw/mcp/coder",
      "headers": {"X-API-Key": "${env:A2AGW_API_KEY}"}
    }
  }
}
```

Claude Agent SDK (Python):

```python
import os
from claude_agent_sdk import ClaudeAgentOptions, query

options = ClaudeAgentOptions(
    mcp_servers={
        "a2agw": {
            "type": "http",
            "url": "https://gw.example.com/a2agw/mcp/coder",
            "headers": {"X-API-Key": os.environ["A2AGW_API_KEY"]},
        }
    },
    allowed_tools=["mcp__a2agw"],  # every tool of this server
)
async for message in query(prompt="Ask the researcher about X", options=options):
    print(message)
```

### Stdio

`a2agw mcp -c a2agw.yaml --agent <id>` serves one listed agent id over stdio, for clients
that start their MCP servers as processes. It runs the gateway without its HTTP server or its
served agents (registering the config's partners as `serve` does), and needs no credentials:
anyone who can run it can read the config. Its calls are standalone, owned by
`sidecar:<id>` (the host's TTL expiry covers them) and capped like a standalone principal's,
for the local caller `local:<id>`. An agent id that is not in `sidecar.mcp.agents` is
refused.

It opens the config's database. With an SQLite `db_url`, do not run it next to an
`a2agw serve` that uses the same file: point the MCP client at that gateway's HTTP endpoint
instead.

```json
{
  "mcpServers": {
    "a2agw": {"command": "a2agw", "args": ["mcp", "-c", "/srv/a2agw/a2agw.yaml", "--agent", "coder"]}
  }
}
```

## Worked example

`examples/software_team` runs the whole sidecar surface in one network
(`uv run python examples/software_team/run_demo.py`, Node 24 needed):

- [`examples/node_coder`](../examples/node_coder/README.md) is a webhook agent in Node's
  standard library. It verifies the signature and timestamp, streams `status`, `text` and
  `done`, consults `security` with its consult token during the turn (a linked call: its
  handle's `inbound_task_id` is the coder's task), and stops when the gateway disconnects.
- [`examples/mcp_client/client.py`](../examples/mcp_client/client.py) is an MCP-only agent.
  It connects to `/a2agw/mcp/pm-desk` with an API key scoped `a2agw:sidecar` (mapped to
  `pm-desk` in `sidecar.clients`), lists the tools, calls `ask_pm` and waits with `a2a_wait`.

The run is one trace and one audit chain; `tests/integration/test_phase3_demo.py` checks both,
and that no secret, consult token or API key reaches a log.

## Limitations

- **No push to sidecar agents (spec §11a.7).** The optional authenticated webhook receiver
  for partner push notifications is deferred to Phase 4+. A sidecar agent follows a long
  partner task by polling: `GET .../tasks/{task_id}`, `POST /wait`, or the MCP tools
  `a2a_check_task` and `a2a_wait`.
- **Token-exchange partners** cannot be consulted from a sidecar (see
  [Consulting partners](#consulting-partners)).
- **One gateway per SQLite file:** don't run `a2agw mcp` (stdio) next to an `a2agw serve` on
  the same SQLite database (see [Stdio](#stdio)).
