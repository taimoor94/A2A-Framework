# Software team demo

Three agents, each built with a different framework, cooperate over A2A from one
`AgentHost`. This is the Phase 1 acceptance check. It shows:

- **Multi-turn input-required.** The architect asks a clarifying question. The PM answers it
  on the same task and context, and the architect finishes.
- **Long tasks with handles.** The security review outlasts the PM's short wait, so the PM
  gets a `working` handle back and calls `a2a_wait` until the review is done.
- **One distributed trace.** Every `a2agw.inbound` and `a2agw.partner_call` span in the run
  shares one trace id. The trace context travels in the call-context extension.

## Run it

```bash
uv run python examples/software_team/run_demo.py            # port 8765, spans to the console
uv run python examples/software_team/run_demo.py --no-trace # no OpenTelemetry
uv run python examples/software_team/run_demo.py --port 9000
```

The script serves the agents with uvicorn on `127.0.0.1` and uses a temporary SQLite
database. It registers `architect` and `security` as `internal` partners from their cards,
then sends "Build a todo API" to `pm` with the a2a-sdk client. It prints:

- the final PM state and report;
- the event timeline from the host's event bus (`kind`, agent, state);
- the trace id.

The console exporter prints only the `a2agw.*` spans. The a2a-sdk's own internal spans are
left out.

## Flow

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

`team.py` has `build_team(base_url, *, db_url, partner_http=None)`. The demo and
`tests/integration/test_software_team.py` both use it.

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
