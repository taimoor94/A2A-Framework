# Software team demo

Agents built with different frameworks, and in different languages, cooperate over A2A from
one `AgentHost`.

**Phase 3 (the default run)** adds two agents that are not Python code in the gateway, the
Phase 3 "done when" check:

- **A non-Python agent.** `coder` is a Node webhook agent ([examples/node_coder](../node_coder/README.md)),
  started as a `node` subprocess on a free loopback port. The gateway signs every invoke
  (HMAC), the coder verifies it, streams NDJSON, and consults `security` itself through the
  outbound REST API with its turn's consult token. That partner call is linked to the coder's
  inbound task (`inbound_task_id` on its handle) and continues the trace.
- **An MCP-only agent.** `pm-desk` ([examples/mcp_client](../mcp_client/client.py)) has no
  A2A code: it connects to `/a2agw/mcp/pm-desk` with an API key scoped `a2agw:sidecar`
  (mapped to `pm-desk` in `sidecar_clients`), lists the tools, calls `ask_pm` with a short
  wait, gets a `working` handle, and calls `a2a_wait` until the PM is done.

With them, auth is on: the agents' own partner calls carry a team API key
(`StaticCredentials`), and all keys and the webhook secret are throwaway values generated per
run and never printed.

**Phase 1 (`--phase1`)**: the three Python agents, asked by an a2a-sdk client. It shows:

- **Multi-turn input-required.** The architect asks a clarifying question. The PM answers it
  on the same task and context, and the architect finishes.
- **Long tasks with handles.** The security review outlasts the PM's short wait, so the PM
  gets a `working` handle back and calls `a2a_wait` until the review is done.
- **One distributed trace.** Every `a2agw.inbound` and `a2agw.partner_call` span in the run
  shares one trace id. The trace context travels in the call-context extension.
- **Signing and audit.** The run generates a throwaway Ed25519 key. Every card the host serves
  is signed, `architect` and `security` are registered from signed cards and verified against
  that key (the `internal` tier requires signatures here), and pm's partner calls carry signed
  call contexts that the agents verify. The audit log records the admissions and partner
  calls; the script prints the signing key id, the number of audit rows and the chain check.

## Run it

```bash
uv run python examples/software_team/run_demo.py            # Phase 3; port 8765, spans to the console
uv run python examples/software_team/run_demo.py --no-trace # no OpenTelemetry
uv run python examples/software_team/run_demo.py --port 9000
uv run python examples/software_team/run_demo.py --phase1   # Python agents only, no Node or MCP
```

The Phase 3 run needs Node 24 on `PATH` and the `mcp` extra (in the dev environment). The
script serves the agents with uvicorn on `127.0.0.1` and uses a temporary SQLite database. It
registers `architect`, `security` and, in Phase 3, `coder` and `pm` as `internal` partners from
their signed cards. Phase 3 sends "Build a todo API" to `pm` from the MCP client; `--phase1`
sends it with the a2a-sdk client. It prints:

- the MCP client's tools and answers (Phase 3), the final PM state and report;
- the event timeline from the host's event bus (`kind`, agent, state);
- the coder's linked partner call and its log (Phase 3);
- the signed-card count and key id, the audit row count and the audit chain check;
- the trace id, when every `a2agw.*` span is in one trace.

The console exporter prints only the `a2agw.*` spans. The a2a-sdk's own internal spans are
left out.

## Flow

Phase 3:

```
pm-desk (MCP client) ── ask_pm(wait_seconds=1) ──▶ /a2agw/mcp/pm-desk ──▶ pm (LangGraph)
     ◀── working (task handle)
  pm ── ask_architect ... ◀── completed: design      (input-required round trip, as below)
  pm ── ask_coder("Implement the design: …") ──▶ coder (Node, webhook, HMAC-signed)
       coder ── POST /a2agw/v1/partners/security/messages (Bearer consult token) ──▶ security
             ◀── completed: "No critical findings. …"
       ◀── completed: code + the review
  pm ── ask_security ... a2a_wait ... ◀── completed  (long task, as below)
pm-desk ── a2a_wait([{pm, task_id}]) ◀── completed: "## Architecture … ## Code … ## Security review …"
```

Phase 1:

```
client ──"Build a todo API"──▶ pm (LangGraph)
  pm ── ask_architect("Design a todo API: …") ──▶ architect
       ◀── input_required: "Which database?"
  pm ── ask_architect("PostgreSQL", same task_id + context_id) ──▶ architect
       ◀── completed: design text
  pm ── ask_security("Review the design: …", wait_seconds=0.5) ──▶ security
       ◀── working (task handle)          security: scanning dependencies
  pm ── a2a_wait([{security, task_id}], seconds=10)               checking authz
       ◀── completed: "No critical findings. …"                   writing report
  pm ──▶ client: "## Architecture … ## Security review …"
```

All three agents run in one host at `/agents/{id}`. The PM reaches its partners over HTTP
like any external partner, so the same code works with agents on other hosts.

## What each framework shows

| Agent | Built with | Served through | Shows |
|---|---|---|---|
| `pm` | LangGraph `StateGraph` + `InMemorySaver` | `GraphAdapter` | Outbound partner tools via `as_langchain_tools`. A scripted fake model: graph nodes call `ask_architect`, `ask_security` and `a2a_wait` directly with `tool.ainvoke(...)` instead of an LLM choosing the tools. |
| `architect` | LangChain `RunnableLambda` with per-thread message history (`thread_id` = A2A `contextId`) | `CallableAdapter` | Input-required. `RunnableAdapter` has no input-required path for plain runnables, so the agent's callable wrapper yields `NeedInput("Which database?")` on the first turn. On the resumed turn it calls the runnable with the answer. |
| `security` | A plain async generator function | `CallableAdapter` (`@agent`) | A long task: three `Status` updates about 0.7 s apart, then `Done(...)`. |
| `coder` (Phase 3) | Node 24, standard library | `WebhookAdapter` | A non-Python agent: signed invokes, NDJSON streaming, a linked consult through the REST API, disconnect as cancel. |
| `pm-desk` (Phase 3) | The `mcp` Python client | The gateway's MCP server | An MCP-only agent: tools listed and called over streamable HTTP, a handle waited on with `a2a_wait`. |

`team.py` has `build_team(base_url, *, db_url, partner_http=None, signing_dir=None,
coder_url=None, coder_secret=None, mcp_key=None, team_key=None)`; with `signing_dir` it
generates the key there and runs signed, with `coder_url` it adds the Node coder, and with
`mcp_key` it turns auth on and serves `pm-desk` over MCP. `run_demo.run_network(port=...,
phase3=True)` runs the whole thing and returns what it saw. The demo,
`tests/integration/test_software_team.py` (Phase 1) and
`tests/integration/test_phase3_demo.py` (Phase 3, skipped without `node`) all use it with
signing on.

## Real LLM (optional)

By default the architect's design text is scripted, so the demo is deterministic and needs no
network. To have Claude write the design, install `langchain-anthropic` and set two variables:

```bash
uv pip install langchain-anthropic
export ANTHROPIC_API_KEY=...
export A2AGW_DEMO_LLM=1
uv run python examples/software_team/run_demo.py
```

The design then comes from `ChatAnthropic(model="claude-opus-5-5", max_tokens=2048)`. The
import is lazy. If `langchain-anthropic` is not installed, the scripted text is used.
`langchain-anthropic` is not a declared dependency of `a2a-gateway`, and this path is
untested. The PM and security agents stay scripted in either mode.
