# a2a-gateway

A framework-agnostic gateway for the [A2A (Agent2Agent) protocol](https://a2a-protocol.org). It works in both directions. **Inbound**, it serves any agent (a plain function, a LangChain runnable, a LangGraph graph) as a standards-compliant A2A server. **Outbound**, it keeps a registry of partner agents, each registered from its Agent Card, and makes them available to your agent as tools (when the agent's code uses `partner_tools`), so the agent's own reasoning decides which partner to consult. It is built on the official `a2a-sdk` and treats every remote party as untrusted by default.

## Features

- One `AgentHost` serves many agents at `/agents/<id>/`, over JSON-RPC and HTTP+JSON, with streaming, cancel, and multi-turn (`input-required`).
- Adapters: plain callables (sync, async, generators), LangChain runnables, and LangGraph graphs (`interrupt()` becomes `input-required`).
- Partner registry with card fetch, pinning, change quarantine, and approval.
- Partner tools with task handles (`ask_<id>`, `a2a_check_task`, `a2a_cancel_task`, `a2a_wait`), and a discovery mode (`find_partners`, `consult_partner`) above 12 partners.
- Resilience on outbound calls: deadline, jittered retries, circuit breaker, per-partner bulkhead.
- Call-context extension: trace, hop budget, deadline, call budget, and re-entry detection across agent networks.
- API-key and JWT auth with per-agent authorization, an SSRF guard, and an untrusted-text envelope for partner output.
- OpenTelemetry tracing, JSON logs, and a read-only admin API with an SSE event stream.
- SQLite task store, with recovery of in-flight tasks on restart.
- A CLI: `init`, `serve`, `partners`, `card validate`, `call`.
- **Conformance:** the inbound side passes the A2A TCK at MUST level. See [docs/conformance.md](docs/conformance.md).

## Install

Requires Python 3.11+.

```bash
uv add a2a-gateway                 # core: callable agents, partners, CLI
uv add "a2a-gateway[langchain]"    # adds the LangChain adapter and tools
uv add "a2a-gateway[langgraph]"    # adds the LangGraph adapter (includes LangChain)
```

`pip install a2a-gateway` works the same way.

## Quickstart (5 minutes)

Scaffold a project, with one echo agent:

```bash
a2agw init myagent
```

```
wrote myagent/a2agw.yaml
wrote myagent/agent.py
wrote myagent/.env.example
```

Start the gateway:

```bash
cd myagent && a2agw serve          # binds 127.0.0.1:8000 by default
```

The scaffold sets `admin_without_auth: true` so you can try the admin API locally. That leaves the admin API open to anyone who can reach the port, so keep the default `--host 127.0.0.1` and configure `auth` (see Configuration) before you bind to `0.0.0.0` with `--host 0.0.0.0`.

The echo agent is now served at `http://localhost:8000/agents/echo/`, and its card is at `/agents/echo/.well-known/agent-card.json`. In another terminal (the `partners` commands read `a2agw.yaml`, so stay in `myagent`, or pass `-c myagent/a2agw.yaml`), call it. `call` takes the agent's base URL (the one in its card, with the trailing slash). It treats the target as a `partner` by default, which requires https, so for a local `http://` agent pass `--tier internal`:

```bash
cd myagent
a2agw call http://localhost:8000/agents/echo/ "hello" --tier internal
```

```
state: TASK_STATE_COMPLETED
echo: hello
```

For an agent behind API-key auth, set `A2AGW_API_KEY` in the environment rather than passing `--api-key`: a key on the command line is visible to other users in `ps` and is saved in your shell history. `--api-key` overrides the variable when both are set.

Register an agent as a partner of your gateway. This fetches its card and saves it to `partners.yaml` next to `a2agw.yaml`. Here the agent registers itself, which is enough to see the flow; use another agent's URL in practice:

```bash
a2agw partners add echo http://localhost:8000/agents/echo/ --tier internal
a2agw partners list
```

```
added echo (internal) hash da7686314f77
ID    TIER      STATUS  HASH          PENDING
echo  internal  active  da7686314f77
```

Restart `a2agw serve` to load new partners. Partners are registered gateway-wide, but an agent only gets them as tools if its code builds them with `partner_tools` / `as_langchain_tools` (see below); the echo agent does not. Open `agent.py` and edit the function: it is a normal Python function.

```python
from a2agw.adapters.callable import agent


@agent(id="echo", description="Echoes the user's message back.")
async def echo(ctx):
    return f"echo: {ctx.text}"
```

## Writing agents

### A callable agent

`@agent` turns a function of `InboundContext` into an `AgentSpec`. The function may return a string, or be a generator yielding strings (streamed as an artifact) and events.

```python
import uvicorn
from a2agw import AgentHost, Done, NeedInput, Status, agent


@agent(id="booker", description="Books a table.")
async def booker(ctx):
    if not ctx.resumed:
        yield NeedInput("For how many people?")  # task becomes input-required
        return
    yield Status("checking availability")
    yield Done(f"Booked a table for {ctx.text}.")


host = AgentHost("http://localhost:8000")
host.add(booker)
uvicorn.run(host.app(), port=8000)
```

`host.run(port=8000)` is a shortcut for the last line. Like uvicorn and `a2agw serve`, it binds `127.0.0.1` by default; pass `host="0.0.0.0"` to accept remote connections, and configure `auth` first.

Events: `Status`, `ArtifactChunk`, `NeedInput`, `NeedAuth`, `Usage`, `Done`, `Failed`, `Reply`.

### A LangGraph agent

`GraphAdapter` runs the graph with `thread_id = contextId`. A LangGraph `interrupt()` ends the turn as `input-required`; the next message on the same task resumes the graph. Use a checkpointer (a persistent one makes `input-required` tasks survive restarts).

```python
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.types import interrupt

from a2agw import AgentHost, AgentSpec, SkillSpec
from a2agw.adapters.langgraph import GraphAdapter


def ask(state: MessagesState):
    answer = interrupt("Which environment?")  # -> input-required
    return {"messages": [("ai", f"Deploying to {answer}")]}


builder = StateGraph(MessagesState)
builder.add_node("ask", ask)
builder.add_edge(START, "ask")
builder.add_edge("ask", END)
graph = builder.compile(checkpointer=InMemorySaver())

deployer = AgentSpec(
    id="deployer",
    name="Deployer",
    description="Deploys a service.",
    skills=[SkillSpec(id="deploy", name="Deploy", description="Deploy a service")],
    adapter=GraphAdapter(graph),
)
host = AgentHost("http://localhost:8000")
host.add(deployer)
```

### An agent that consults partners

`partner_tools(host.partners)` projects the active partners as tools. `as_langchain_tools(tools, host.client)` turns them into LangChain `StructuredTool`s, and each tool returns a JSON string. `host.client` exists once the host has started, so build the tools inside the agent run, as the demo does.

```python
from pathlib import Path

from a2agw import AgentHost, partner_tools
from a2agw.adapters.langchain import as_langchain_tools

host = AgentHost("http://localhost:8000", partners_path=Path("partners.yaml"))


def tools_for_this_run():
    return as_langchain_tools(partner_tools(host.partners), host.client)
```

Give those tools to a tool-calling model, a LangGraph `ToolNode`, or call them directly. A partner call that outlasts `wait_seconds` returns a `working` result with a task handle; poll it with `a2a_check_task` or `a2a_wait`. If a partner needs input, the result has state `input_required` and a `question`; answer by calling the same tool again with that `task_id` and `context_id`. Without LangChain, `a2agw.adapters.callable.as_functions(tools, client)` gives plain async functions.

## Demo

[`examples/software_team`](examples/software_team/README.md) runs three agents built with different frameworks (LangGraph, LangChain, plain Python) from one host. It shows `input-required` across agents, a long task polled through a handle, and one distributed trace. Run it with `uv run python examples/software_team/run_demo.py`.

## Security defaults

- **Trust tiers.** Every partner has a tier: `internal`, `partner`, or `public`. The SSRF guard checks outbound card and endpoint URLs. Outside the `internal` tier, hostnames are resolved and private, loopback, link-local, and metadata addresses are refused. The `internal` tier skips the address checks, so use it only for agents you operate.
- **https.** Required for every tier except `internal`.
- **Pinned cards and quarantine.** Endpoints come from the card you registered. If a refreshed card changes, the partner is quarantined and its old card stays in force until you approve the new one against its hash:
  ```bash
  a2agw partners verify acme            # reports "unchanged" or "quarantined"
  a2agw partners list                   # shows the PENDING flag and the hash
  a2agw partners approve acme --hash <hash-from-list>
  ```
- **Access control needs `auth`.** Without an `auth` section every caller is anonymous and `AgentAccess` is not enforced, so that setup is for local development only. Once `auth` is set, anonymous callers are always denied on agent endpoints. Agent cards and healthz are public either way, so `allow_anonymous: true` opens nothing extra: it only changes the answer to a request without credentials on an agent route from 401 (unauthenticated) to 403 (forbidden).
- **Principals are prefixed.** `AgentAccess(allowed_principals=...)` takes `key:<principal_id>` for API keys and `jwt:<sub>` for JWTs. An unprefixed id matches nothing.
- **Untrusted partner text.** Text from partners is capped at 64 KiB, and results carry `provenance.untrusted = true`. `UNTRUSTED_NOTE` is appended to the partner tools' descriptions so the model treats partner output as data, not instructions. Binary artifacts are never inlined.
- **Call-context limits.** Every call carries a call context: at most 8 hops by default, an absolute deadline (the default inbound ceiling is 1 hour; it is checked when a call is admitted, not enforced mid-run), an optional call budget (`max_calls`), and the path of agents already involved. A call that comes back to an agent already on its path is rejected unless that agent sets `allow_reentry`. Limits only ever tighten as the context travels. Cancelling an inbound task cancels the partner tasks it started.
- **Inbound limits.** Request bodies up to 10 MiB and 64 parts per message.
- **Admin.** The admin API needs a principal with the `a2agw:admin` scope. With no `auth` configured it is closed, unless you set `admin_without_auth: true` (development only).
- **Secrets.** By design, secrets are kept out of logs, traces, the admin API, and error messages, and credentials are read from the environment at call time. Treat that as the intent, not a guarantee, and review your own agent code and exporters.
- **Development switch.** `A2AGW_DEV=1` allows plain `http://` for the `partner` and `public` tiers. It is for local development only; never set it in production.

```python
from a2agw import AgentAccess, AuthConfig

# auth.api_keys holds sha256 hashes of keys, never the keys themselves
access = AgentAccess(
    allowed_principals=frozenset({"key:ci-bot", "jwt:user-42"}),
    required_scopes=frozenset({"deploy"}),
)
# attach it to an agent: @agent(id="deployer", description="...", access=access)
```

## Observability

```python
from a2agw import setup_telemetry

setup_telemetry("my-gateway")  # JSON logs plus an OpenTelemetry tracer provider
```

Or set `telemetry:` in `a2agw.yaml`. Two span names are emitted: `a2agw.inbound` for each inbound task and `a2agw.partner_call` for each outbound call. The trace context travels between agents in the call-context extension (`https://a2agw.dev/ext/call-context/v1`), so one request is one trace across the whole network. Spans carry identifiers and states, never message text or credentials. To export over OTLP, pass your own exporter to `setup_telemetry(exporter=...)`, or set `telemetry.otlp_endpoint` (needs `opentelemetry-exporter-otlp`).

The read-only admin API is mounted on the host:

| Endpoint | Returns |
|---|---|
| `GET /a2agw/admin/healthz` | Liveness (no auth) |
| `GET /a2agw/admin/agents` | Hosted agents and their skills |
| `GET /a2agw/admin/partners` | Partners with tier, status, card hash, breaker state, in-flight calls |
| `GET /a2agw/admin/tasks` | Task index; filters `agent`, `state`, `limit`, `cursor` |
| `GET /a2agw/admin/events` | Server-sent event stream (`task.state`, `partner.call`) |

## Configuration

`a2agw.yaml` is read by `a2agw serve` and the `partners` commands. `${VAR}` and `${VAR:-default}` are replaced from the environment in string values only (use `$$` for a literal `$`). Unknown fields are rejected.

```yaml
base_url: ${A2AGW_BASE_URL:-http://localhost:8000}   # public URL, used in agent cards
db_url: sqlite+aiosqlite:///a2agw.db                 # task store
partners_file: partners.yaml                         # partner registry, relative to this file
admin_without_auth: false                            # true = open admin API (development only)

auth:                                                # omit for no authentication
  allow_anonymous: false                             # true: no-credential agent calls get 403, not 401
  api_keys:                                          # key: sha256 hex of the API key
    "<64-char sha256 hex>":
      principal_id: ci-bot                           # becomes key:ci-bot
      scopes: [a2agw:admin, deploy]
  jwt:
    issuer: https://login.example.com
    audience: a2agw
    jwks_url: https://login.example.com/.well-known/jwks.json   # or public_key_pem: |
    scopes_claim: scope

agents:                                              # module:attribute, importable from this dir
  - spec: agent:echo                                 # an AgentSpec, or a zero-argument factory

partners:                                            # registered at startup if not present
  - id: acme
    url: https://agents.acme.example/agents/support/ # or card_file: cards/acme.json
    tier: partner                                    # internal | partner | public
    credential_ref: acme
    tags: [support]

credentials:                                         # credential_ref -> header filled from env
  acme:
    header: Authorization
    env: ACME_TOKEN                                  # the env var holds the full header value

telemetry:
  service_name: my-gateway
  otlp_endpoint: ${OTLP_ENDPOINT:-}                  # optional
```

Generate an API-key hash with `printf %s "$KEY" | shasum -a 256 | cut -d' ' -f1`.

## Architecture

```
                 +------------------- a2agw ---------------------+
   inbound A2A   |  Serve: card, JSON-RPC + REST, auth, task     |
  ─────────────▶ |  store, executor ──▶ adapter ──▶ your agent   |
                 |                      (callable / LangChain /  |
                 |                       LangGraph)              |
                 |                           │ partner tools     |
   outbound A2A  |  Consult: registry, PartnerClient             |
  ◀───────────── |  (deadline, retry, breaker, SSRF guard)       |
                 |                                               |
                 |  Cross-cutting: call context, OpenTelemetry,  |
                 |  event bus, admin API                         |
                 +-----------------------------------------------+
```

The core never imports a framework; adapters live in `a2agw.adapters.<name>` behind extras. See the [design spec](docs/superpowers/specs/2026-10-25-a2a-gateway-framework-design.md) and the [Phase 1 plan](docs/superpowers/plans/2026-10-25-phase1-core.md).

## Roadmap

Phase 1 (this release) is the core described above. Everything below is planned and not implemented yet.

- **Phase 2, hardening:** signed cards, OAuth2 client credentials and mTLS, a policy engine, push notifications, a Postgres store, audit log, and fault-injection tests.
- **Phase 3, gateway:** a sidecar service for agents in any language, an MCP gateway, adapters for CrewAI, OpenAI Agents, Claude Agent SDK, ADK, AG2 and LlamaIndex, and a Docker image.
- **Phase 4, control plane:** a central registry, and the Console (a web UI to register and approve partners, edit policy, and inspect cross-agent traces), with SSO and RBAC.
- **Phase 5, clusters and projects:** agent teams (Clusters) with an orchestrator, a project board, and human-in-the-loop in the Console.

gRPC is not offered today.

## License

Apache-2.0. See [LICENSE](LICENSE).

### mTLS

Outbound: give `PartnerClient(tls={"ref": TlsClientConfig(cert_file, key_file, ca_file)})` and set `tls_ref` on a partner record; its calls then use a dedicated TLS 1.2+ client that presents that certificate and trusts `ca_file`. An unknown `tls_ref` fails closed (`unavailable`, "tls config missing"). Inbound: `a2agw serve --ssl-certfile F --ssl-keyfile F [--ssl-ca-certs F --require-client-cert]` (or `AgentHost.run(ssl_*=...)`). The client certificate is verified at the TLS layer only; ASGI servers do not expose it, so identity still comes from the API key or JWT.
