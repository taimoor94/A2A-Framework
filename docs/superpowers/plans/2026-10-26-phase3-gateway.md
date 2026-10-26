# Phase 3 (Gateway) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let agents written in any language, and any MCP-capable agent, join an a2agw network. The gateway runs as a sidecar that serves A2A on their behalf and gives them partners over REST and MCP. Native adapters cover six more Python frameworks, and a Docker image ships the sidecar.

**Architecture:**
- **New package `a2agw.gateway`.** It holds the sidecar's wire protocol, consult tokens, the outbound REST API and the MCP server. Two new inbound adapters, `WebhookAdapter` and `StdioAdapter`, turn an external process into an ordinary `InboundAdapter`. Everything else (store, auth, policy, audit, push, call context) is reused unchanged.
- **Linked outbound calls.** An external agent's partner calls carry a short-lived *consult token* that was issued for one inbound run. Its calls are therefore linked to that run: they get cascade-cancel, the fan-out cap, and hop/budget propagation, exactly like an embedded Python agent.
- **Framework adapters.** Each one lives in `a2agw/adapters/<fw>.py` as an optional extra. Each provides an inbound adapter plus a tool projector, and is tested with a fake model.

**Tech Stack:**
- Python 3.12 (supports 3.11 and later), uv.
- `a2a-sdk>=1.2.3,<2`, Starlette, `httpx<0.29`.
- `mcp>=2.3,<3` (low-level `Server`, stdio and streamable-HTTP transports).
- Adapter extras: `openai-agents>=0.24`, `claude-agent-sdk>=0.2.174`, `google-adk>=2.13`, `ag2>=1.2`, `llama-index-core>=0.14.25`, `crewai>=1.15`.
- Node 24 (the non-Python example agent; standard library only). Docker.

**Spec:** `docs/superpowers/specs/2026-10-25-a2a-gateway-framework-design.md`. Phase 3 is described in §7.7, §7.1, §7.3, §7.9, §9 and §11a.7. The spec is binding and this plan argues from it.

## Global Constraints

- The core (`a2agw` minus `a2agw.adapters.*`) imports no agent framework and does not import `mcp`. Spec §4: "the core imports any agent framework" is an anti-goal. `a2agw.gateway.mcp_server` is imported only when MCP is configured or used.
- Every framework and `mcp` is an optional extra. A missing extra raises `ImportError`, and the message names the extra (`pip install 'a2a-gateway[openai]'`).
- Dependencies: `a2a-sdk>=1.2.3,<2`, `httpx>=0.28,<0.29`, `httpcore>=1.0,<2`, `mcp>=2.3,<3`.
  - CrewAI requires `mcp<2` and `openai<3`, so the `crewai` extra is declared in uv as conflicting with the `mcp` and `openai` extras (`[tool.uv] conflicts`).
  - CrewAI tests run in their own environment (see Task 10).
- Python ≥ 3.11 and uv. Every test is deterministic: fake models only, with no network, API keys or LLM calls.
- Security is fail-closed:
  - All outbound HTTP goes through the guarded network (`a2agw.consult.guarded_net`).
  - Secrets come only from `*_env` or files, and never appear in logs, errors, audit rows or wire payloads sent to agents.
  - Untrusted text keeps the `UNTRUSTED_NOTE` framing.
- The public API is additive. The A2A TCK MUST level stays at 0 failures. SQLite and PostgreSQL both work, and schema changes go through `_ddl` / `retry_ddl` (the `_ADDED_COLUMNS` pattern).
- "Done when" (spec §9): **a non-Python agent and an MCP-only agent join the demo network.**
- Test gate: `uv run pytest -q -W error` passes when run alone, `uv run ruff check` is clean, and the CrewAI suite command from Task 10 is green.

## Review Focus

1. **A webhook or stdio agent that hangs, stalls mid-stream, or emits malformed or oversized events.** The task fails within its deadline with a generic reason. Memory stays bounded and nothing leaks into the A2A response. Tests: Tasks 1 and 2.
2. **A consult token reused after its run ended, used for a different agent, or replayed from logs.** It is rejected with 401, and the token value is never logged or audited. Test: Task 3.
3. **The stdio agent process crashing while several runs are in flight.** Every in-flight run fails with "agent process exited", the process restarts with back-off, and the next run succeeds. Test: Task 2.
4. **An MCP session whose partner set changes mid-session** (a partner quarantined, removed, or forbidden by policy). The tool list reflects the change, and a call to the stale tool returns `unavailable` without contacting the partner. Test: Task 4.
5. **An inbound task cancelled while its external agent is running.** The agent is told (the stream is closed, or a stdio `cancel` op is sent), and every partner task started with that run's consult token is cancelled through the existing cascade. Tests: Tasks 1, 2 and 3.

---

## File Structure

| File | Responsibility |
|---|---|
| `src/a2agw/gateway/__init__.py` | Package marker. It imports nothing heavy. |
| `src/a2agw/gateway/protocol.py` | The sidecar wire protocol: building `InvokeRequest`, parsing events back into `AgentEvent`, and the limits. Shared by the webhook and stdio adapters. |
| `src/a2agw/adapters/webhook.py` | `WebhookAdapter`, for inbound work over HTTP NDJSON. |
| `src/a2agw/adapters/stdio.py` | `StdioAdapter`, for inbound work over a supervised long-lived subprocess speaking JSON lines. |
| `src/a2agw/gateway/tokens.py` | `ConsultTokens`: issue, resolve and revoke run-scoped consult tokens. |
| `src/a2agw/gateway/rest.py` | The outbound REST API (`/a2agw/v1/...`). |
| `src/a2agw/gateway/mcp_server.py` | The outbound MCP server: per-agent tool list, call handling, the stdio runner and the streamable-HTTP mount. |
| `src/a2agw/adapters/{openai_agents,claude_agent,adk,ag2,llamaindex,crewai}.py` | One framework adapter each. |
| `tests/adapters/contract.py` | A shared contract kit that every inbound adapter and tool projector must pass. |
| `docs/sidecar.md` | The protocol reference for non-Python agent authors (webhook, stdio, REST, MCP, with JSON examples). |
| `Dockerfile`, `.dockerignore`, `examples/docker/` | The image and a compose example. |
| `examples/node_coder/agent.mjs`, `examples/mcp_client/client.py` | The Phase 3 "done when" agents. |

---

### Task 1: Sidecar protocol and `WebhookAdapter`

**Files:**
- Create: `src/a2agw/gateway/__init__.py`, `src/a2agw/gateway/protocol.py`, `src/a2agw/adapters/webhook.py`, `docs/sidecar.md` (the webhook section).
- Modify: `src/a2agw/config.py` (agent entries for external agents), `src/a2agw/__init__.py` (export `WebhookAdapter`).
- Test: `tests/gateway/test_protocol.py`, `tests/adapters/test_webhook.py`, `tests/test_config.py`.

**Interfaces:**
- Consumes: `InboundContext` and the `AgentEvent` union (`a2agw.core`), `guarded_async_client(tier=...)` (`consult/guarded_net.py`), and `stream_events` (`adapters/_stream.py`).
- Produces:
  - `PROTOCOL = "a2agw.invoke/1"`.
  - `build_invoke(ctx: InboundContext, *, consult: ConsultGrant | None, deadline: float | None) -> dict[str, Any]`. `ConsultGrant` is defined here as a dataclass `{url: str, token: str, expires_at: float}`; Task 3 fills it.
  - `parse_event(obj: Any) -> AgentEvent`, which raises `ProtocolError(ValueError)`.
  - The limits `MAX_LINE_BYTES = 1 << 20`, `MAX_RESPONSE_BYTES = 16 << 20` and `MAX_EVENTS = 10_000`.
  - `WebhookAdapter(url: str, *, secret: str | None = None, timeout_s: float = 300.0, tier: Tier = "internal", http: httpx.AsyncClient | None = None, durable_sessions: bool = False, consult: Callable[[InboundContext], Awaitable[ConsultGrant | None]] | None = None)`.
  - `sign(secret: str, ts: str, body: bytes) -> str`, which returns `"v1=" + hex(hmac_sha256(secret, f"{ts}.".encode() + body))`.

**Decisions:**
- **The invoke body** is JSON: `{protocol, agent_id, task_id, context_id, resumed, text, parts: [A2A Part as JSON via MessageToDict], metadata, caller: {id, kind} | null, consult: {url, token, expires_at} | null, deadline: <epoch seconds> | null}`.
  - The caller's raw credentials are never included.
- **Request headers:** `Content-Type: application/json`, `Accept: application/x-ndjson, application/json`, `X-A2AGW-Protocol: a2agw.invoke/1`, `X-A2AGW-Timestamp: <unix seconds>`, and `X-A2AGW-Signature: v1=<hex>` (only when a secret is set).
- **Response:**
  - `application/x-ndjson`: one event per line.
  - Or `application/json`, with either `{"text": "..."}` (meaning `Done(text)`) or `{"events": [...]}`.
- **Wire events** map to `AgentEvent` as follows:

  | Wire `type` | Fields | `AgentEvent` |
  |---|---|---|
  | `status` | `text` | `Status` |
  | `artifact` | `parts`, `name?`, `artifact_id?`, `append?`, `last?` | `ArtifactChunk` |
  | `text` | `text` | Streamed through `stream_events` as the "output" artifact |
  | `need_input` | `question` | `NeedInput` |
  | `need_auth` | `scheme`, `detail?` | `NeedAuth` |
  | `usage` | `tokens_in`, `tokens_out`, `cost` | `Usage` |
  | `done` | `text?` | `Done` |
  | `failed` | `error` | `Failed` |
  | `reply` | `text` | `Reply` |

  Parts are parsed with `ParseDict` into `a2a.types.Part`. Anything unknown or invalid raises `ProtocolError`.
- **Failures** (the reason the A2A caller sees is in quotes; the HTTP body is never included):
  - non-2xx: `Failed("agent returned HTTP <code>")`;
  - connection error: `Failed("agent unreachable")`;
  - a stream that breaks: `Failed("agent connection lost")`;
  - a `ProtocolError` or exceeded limit: `Failed("agent protocol error")`, with the detail logged at WARNING, not values;
  - `timeout_s` exceeded: `Failed("agent timed out")`.
- **A clean end of stream** with no terminal event (`done`, `failed`, `need_input`, `need_auth` or `reply`) gives `Done()`.
- **Cancellation:** when `run()` is cancelled (the A2A task is cancelled), the response is closed. Closing the connection is the cancel signal, as documented in `docs/sidecar.md`.
- **Config:** `GatewayConfig.agents` items become `AgentRef | ExternalAgentConfig`.
  - `ExternalAgentConfig` has: `id`, `name`, `description`, `skills: list[SkillSpec-like] (min 1)`, optional `input_modes`/`output_modes`, `durable_sessions: bool = False`, and exactly one of `webhook: {url, secret_env?, timeout_s?, tier?}` or `stdio: {...}` (Task 2).
  - An inline `secret` key is rejected by the existing inline-secret guard.
  - `build_host` turns each entry into an `AgentSpec` with the adapter.

- [ ] **Step 1: Write the failing tests.**
  - `tests/gateway/test_protocol.py`:
    - `test_build_invoke_shape` checks the keys above, that the parts round-trip, and that there is no credential field;
    - `test_parse_each_event_type` is parametrized over all nine types;
    - `test_parse_rejects_unknown_type_and_bad_part`;
    - `test_sign_matches_reference` checks a fixed secret, ts and body against a hard-coded hex value computed with the `hmac` module in the test.
  - `tests/adapters/test_webhook.py` (the agent is a Starlette app served through `httpx.ASGITransport`):
    - `test_ndjson_stream_maps_to_events`;
    - `test_plain_json_text_completes`;
    - `test_signature_headers_present_and_valid`;
    - `test_http_500_fails_without_body` (the body contains a `SECRET-MARKER`, which must not appear in the event);
    - `test_malformed_line_fails_protocol_error`;
    - `test_oversized_line_fails` (MAX_LINE_BYTES + 1);
    - `test_stall_times_out` (`timeout_s=0.2`, the agent never ends);
    - `test_cancel_closes_stream` (the agent observes a disconnect);
    - `test_metadata_ip_refused_on_internal_tier` (`http://169.254.169.254/` gives `Failed("agent unreachable")` with no request made);
    - `test_end_without_terminal_is_done`.
  - `tests/test_config.py`:
    - `test_external_webhook_agent_builds_spec`;
    - `test_external_agent_needs_exactly_one_transport`;
    - `test_webhook_inline_secret_rejected`.
- [ ] **Step 2:** Run `uv run pytest tests/gateway/test_protocol.py tests/adapters/test_webhook.py tests/test_config.py -q`. Expected: FAIL (`ModuleNotFoundError: a2agw.gateway`).
- [ ] **Step 3:** Implement `protocol.py`, `WebhookAdapter` and the config entries as decided above. Use an end-to-end deadline for `timeout_s`, and stream with `client.stream("POST", ...)` and `aiter_lines`, counting bytes against the limits.
- [ ] **Step 4: Add the integration test.**
  - `tests/integration/test_webhook_agent.py::test_a2a_call_reaches_webhook_agent`: an `AgentHost` with one external webhook agent (ASGI fake). An A2A `SendMessage` through the host completes with the agent's text.
  - In the same file, `test_a2a_cancel_closes_webhook_stream`.
- [ ] **Step 5:** Run the full suite and ruff. Write the webhook section of `docs/sidecar.md`: request, response, events, signature verification snippet (pseudo-code), limits and cancel semantics.
- [ ] **Step 6:** Commit with `feat(gateway): sidecar invoke protocol and webhook adapter`.

---

### Task 2: `StdioAdapter` (supervised subprocess, JSON lines)

**Files:**
- Create: `src/a2agw/adapters/stdio.py`.
- Modify: `src/a2agw/config.py` (the `stdio:` transport), `src/a2agw/serve/host.py` (start and stop adapters that have a lifecycle), and the stdio section of `docs/sidecar.md`.
- Test: `tests/adapters/test_stdio.py`, plus a fixture agent in `tests/adapters/stdio_agent.py` (a Python script used as the external process).

**Interfaces:**
- Consumes: `build_invoke` and `parse_event` from Task 1.
- Produces:
  - `StdioAdapter(command: list[str], *, cwd: Path | None = None, env: Mapping[str, str] | None = None, max_concurrency: int = 16, timeout_s: float = 300.0, durable_sessions: bool = False, consult=None)`.
  - Methods `async start()` and `async stop()`.
  - A host lifecycle hook: `AgentHost` calls `await adapter.start()` at startup and `await adapter.stop()` at shutdown for any adapter that has both methods. This is an additive duck-typed protocol, `LifecycleAdapter`, in `core/spi.py`.

**Decisions:**
- **Framing:**
  - The gateway writes to the agent's stdin: `{"op":"invoke","id":<run id>,"request":<invoke body>}`, `{"op":"cancel","id":<run id>}` and `{"op":"shutdown"}`.
  - The agent writes to stdout: `{"id":<run id>,"event":<wire event>}`.
  - Stdout carries the protocol only. Stderr is forwarded to the logger `a2agw.agent.<agent_id>` at INFO, with each line capped at 4 KiB.
- **The run id** is `uuid4().hex`. A run ends at its first terminal event, or when the process exits.
- **Supervision:**
  - The process starts lazily on the first invoke (or at `start()`).
  - On exit, every in-flight run gets `Failed("agent process exited")`.
  - Restart back-off is 1, 2, 4 … up to 30 s; it resets after 60 s of uptime.
  - Invokes during back-off wait up to their timeout, then fail with "agent unavailable".
- **Shutdown:** send `shutdown`, close stdin, wait 5 s, then `terminate()`, wait 2 s, then `kill()`.
- **Environment:**
  - Only `PATH`, `HOME`, `LANG`, `TZ` and any `PYTHONPATH`, plus the configured `env` (whose values come from `env_from: {NAME: ENV_VAR}`; no inline secrets).
  - The parent's environment is never passed through wholesale.
- **Limits:** the same per-line and per-run limits as Task 1. A malformed line fails only the run it names; an unparseable line with no id is logged and ignored.

- [ ] **Step 1: Write the failing tests** in `tests/adapters/test_stdio.py`. Each starts `[sys.executable, "-I", "tests/adapters/stdio_agent.py", <mode>]`.
  - `test_invoke_streams_events`;
  - `test_concurrent_runs_are_multiplexed` (8 runs, each gets its own text);
  - `test_cancel_sends_cancel_op` (the fixture records ops to a temp file);
  - `test_crash_fails_inflight_and_restarts` (in mode `crash-after-first`: 3 in-flight runs all fail "agent process exited", then the next invoke succeeds);
  - `test_env_is_not_inherited` (set `A2AGW_TEST_SECRET` in the parent; the fixture reports it absent);
  - `test_stderr_forwarded_and_capped`;
  - `test_shutdown_terminates_process` (no zombie: the pid is gone after `stop()`);
  - `test_malformed_line_fails_only_that_run`.
- [ ] **Step 2:** Run `uv run pytest tests/adapters/test_stdio.py -q`. Expected: FAIL (`ModuleNotFoundError`).
- [ ] **Step 3:** Implement the adapter with `asyncio.create_subprocess_exec`, one reader task routing events into per-run `asyncio.Queue`s, and a supervisor task. Then add the host lifecycle hook.
- [ ] **Step 4:** Add `tests/test_config.py::test_external_stdio_agent_builds_spec` and `tests/integration/test_webhook_agent.py::test_a2a_call_reaches_stdio_agent`.
- [ ] **Step 5:** Run the full suite and ruff, then commit with `feat(gateway): supervised stdio agent adapter`.

---

### Task 3: Consult tokens and the outbound REST API

**Files:**
- Create: `src/a2agw/gateway/tokens.py`, `src/a2agw/gateway/rest.py`.
- Modify:
  - `src/a2agw/consult/handles.py`: add a nullable `owner` column through `_ADDED_COLUMNS`, plus `record(..., owner=)`.
  - `src/a2agw/serve/reap.py` and `serve/host.py`: TTL expiry also covers handles with no inbound task whose `owner` is a sidecar owner of this host.
  - `src/a2agw/serve/host.py`: mount the REST routes and issue grants for external adapters.
  - `src/a2agw/config.py`: the `sidecar:` section.
  - `docs/sidecar.md`: the REST section.
- Test: `tests/gateway/test_tokens.py`, `tests/gateway/test_rest.py`, `tests/serve/test_ttl_scope.py`.

**Interfaces:**
- Consumes:
  - `invoke` and the `PartnerTool` kinds (`consult/tools.py`).
  - `host.partner_tools(agent_id)`.
  - The contextvars `current_inbound_task`, `current_call`, `current_principal` and `current_agent` (`context/call_context.py`).
  - The fan-out cap and caller-slot machinery (`serve/limits.py`, `PartnerClient`).
- Produces:
  - `ConsultTokens(ttl_s: float = 3600)` with:
    - `issue(agent_id: str, inbound_task_id: str, call: CallContext | None, caller: Principal | None) -> ConsultGrant`;
    - `resolve(token: str) -> Binding | None`;
    - `revoke_task(inbound_task_id: str) -> None`;
    - `Binding` is a dataclass `{agent_id, inbound_task_id, call, caller, expires_at}`.
  - `rest_routes(host: AgentHost) -> list[Route]`, mounted at `/a2agw/v1`.
  - `AgentHost.consult_tokens` and `AgentHost.sidecar_owner(agent_id) -> str` (which returns `f"sidecar:{agent_id}"`).

**Decisions:**
- **Tokens:**
  - A token is `secrets.token_urlsafe(32)`, stored only as its SHA-256 digest.
  - It expires at the earliest of the run end (revoked in the adapter's `finally` through the host), the inbound deadline, and `ttl_s`.
  - A token is never logged, audited or echoed. Audit rows carry `token_hash[:12]` only.
- **Grants** are issued by `AgentHost` for external adapters (the webhook and stdio adapters' `consult` callable). `ConsultGrant.url` is `f"{base_url}/a2agw/v1"`.
- **Routes** (JSON in, the tool envelope out; every response has `Cache-Control: no-store`):
  - `GET /partners`: `[{name, description, parameters, partner_id, kind}]` for the agent's visible tools.
  - `POST /partners/{partner_id}/messages`: the body is the consult tool arguments.
  - `GET /partners/{partner_id}/tasks/{task_id}`: check.
  - `POST /partners/{partner_id}/tasks/{task_id}/cancel`.
  - `POST /wait`: body `{tasks:[{partner_id,task_id}], seconds}`.
  - `POST /find`: body `{need, k}`.
- **Two ways to authenticate**, both resolving to an `agent_id`:
  1. **Linked:** `Authorization: Bearer <consult token>`. The binding sets the contextvars, so the call links to the inbound task (cascade cancel, fan-out cap, call context, `on_behalf_of` = the binding's caller).
  2. **Standalone:** the gateway's normal auth (API key or JWT) with scope `a2agw:sidecar`, plus the header `X-A2AGW-Agent: <agent_id>`. The agent id must be allowed for that principal by `sidecar.clients: {<principal id>: [agent ids]}`. These calls are unlinked: the handle `owner` is `sidecar:<agent_id>`, there is no inbound task, and the call context is a fresh root.

  Anything else gets 401. An agent id the principal is not allowed gets 403. Both are audited (`sidecar.denied`).
- **Routing:** forbid and egress classification are applied as for the agent (`current_agent` = agent_id). A partner not visible to that agent gives `{"state":"unavailable","reason":"unknown partner"}`.
- **Unlinked handles:** the TTL reaper expires these when `owner` is in `{sidecar_owner(a) for a in host-known sidecar agents}`. This closes the Phase 2 limitation "consults with no inbound task never expire" for sidecar traffic.
- **Request body cap:** 256 KiB, rejected with 413.

- [ ] **Step 1: Write the failing tests.**
  - `test_tokens.py`:
    - `test_issue_resolve_revoke`;
    - `test_expired_token_unresolvable`;
    - `test_only_digest_stored` (`token not in repr(store)`).
  - `test_rest.py` (host with fake partner apps, as in the existing `tests/consult` fixtures):
    - `test_linked_consult_links_inbound_task` (the handle row's `inbound_task_id` is the run's task);
    - `test_cancel_inbound_cascades_to_token_started_partner_task`;
    - `test_revoked_token_401`;
    - `test_token_for_other_agent_cannot_widen_routing` (the token binds agent `a`; `X-A2AGW-Agent: b` is ignored; routing is per `a`);
    - `test_standalone_needs_scope_and_mapping` (401 without the scope, 403 for an unmapped agent);
    - `test_forbidden_partner_unavailable`;
    - `test_fanout_cap_applies_to_linked_calls`;
    - `test_hop_budget_propagates` (the partner receives hop = inbound hop + 1);
    - `test_token_never_logged_or_audited` (caplog at DEBUG plus audit rows, with no token substring);
    - `test_body_cap_413`.
  - `test_ttl_scope.py::test_unlinked_sidecar_handles_expire_for_owner_only`.
- [ ] **Step 2:** Run `uv run pytest tests/gateway -q`. Expected: FAIL.
- [ ] **Step 3:** Implement the tokens, the routes, the handle `owner` column (with migration), the reaper scope and the `sidecar` config (`sidecar: {clients: {principal: [agent ids]}}`, default empty).
- [ ] **Step 4: Wire it into the webhook and stdio adapters.**
  - The invoke `consult` field is filled; the grant is revoked when the run ends.
  - Add `tests/integration/test_webhook_agent.py::test_webhook_agent_consults_partner_with_token`, in which the agent fake reads `consult.url` and `consult.token` and calls `POST /partners/p/messages`.
- [ ] **Step 5:** Run the full suite (including the Postgres-marked tests) and ruff. Write the REST section of `docs/sidecar.md`, then commit with `feat(gateway): consult tokens and outbound REST API`.

---

### Task 4: Outbound MCP server

**Files:**
- Create: `src/a2agw/gateway/mcp_server.py`.
- Modify:
  - `src/a2agw/serve/host.py`: mount `/a2agw/mcp/{agent_id}` when `mcp` is enabled.
  - `src/a2agw/cli.py`: add `a2agw mcp`.
  - `src/a2agw/config.py`: the `sidecar.mcp: {enabled: bool = false, agents: [ids]}` section.
  - `pyproject.toml`: the `mcp` extra.
  - `docs/sidecar.md`: the MCP section, including Claude Code, Cursor and Claude Agent SDK config snippets.
- Test: `tests/gateway/test_mcp_server.py`, `tests/test_cli.py`.

**Interfaces:**
- Consumes: Task 3's auth resolution (consult token, or standalone principal plus agent mapping), `invoke` and `host.partner_tools(agent_id)`.
- Produces:
  - `build_mcp_server(host: AgentHost, agent_id: str) -> mcp.server.lowlevel.Server`.
  - `mcp_asgi_app(host: AgentHost) -> ASGIApp`, which serves streamable HTTP per agent behind the gateway auth.
  - `async run_stdio(host: AgentHost, agent_id: str) -> None`.

**Decisions:**
- **SDK:** use `mcp>=2.3`'s low-level `Server(name="a2agw-<agent_id>", on_list_tools=..., on_call_tool=...)`. Verify the handler signatures against the installed `mcp` and record them in the ledger's context notes. There is no `FastMCP`/`MCPServer`, because the tool list is dynamic.
- **Tools:**
  - `host.partner_tools(agent_id)`, which already includes the companion tools.
  - Each becomes `Tool(name, description + "\n\n" + UNTRUSTED_NOTE, inputSchema=<parameters with every "x-" key removed>)`. The original schema, with its `x-` limits, still validates through `invoke`.
- **Call result:** `CallToolResult(content=[TextContent(json.dumps(envelope))], structuredContent=envelope, isError=state in {"failed","rejected"})`. A call to a tool not in the current list gives `isError=True` with `{"state":"unavailable","reason":"unknown tool"}`.
- **List changes:** a registry listener plus a policy reload send `notifications/tools/list_changed` to open sessions where the SDK supports it. In every case, each `list_tools` call recomputes the list.
- **HTTP transport:** `StreamableHTTPSessionManager`, mounted at `/a2agw/mcp/{agent_id}`.
  - Auth is identical to Task 3. A consult token links the session's calls to the inbound run; a standalone principal needs `a2agw:sidecar` and the mapping.
  - `agent_id` must be listed in `sidecar.mcp.agents` (404 otherwise).
  - Use the SDK's transport security settings with DNS-rebinding protection on, allowing the configured `base_url` host.
- **CLI:** `a2agw mcp -c a2agw.yaml --agent <id>` runs a standalone host without the HTTP server.
  - It runs `startup()` (no served agents), then `run_stdio`, then `shutdown()`.
  - Calls are unlinked, owned by `sidecar:<id>`.
  - The CLI refuses an `<id>` that is not in `sidecar.mcp.agents`.
  - Document that an SQLite `db_url` must not be shared with a running `serve`, and point to the HTTP transport instead.

- [ ] **Step 1: Write the failing tests.** `test_mcp_server.py` uses the `mcp` client (`ClientSession` over the SDK's in-memory or streamable-HTTP client transport against the ASGI app).
  - `test_lists_partner_and_companion_tools`;
  - `test_call_returns_envelope_structured`;
  - `test_untrusted_note_in_descriptions`;
  - `test_quarantined_partner_disappears_and_stale_call_unavailable` (no request reaches the partner);
  - `test_forbidden_partner_hidden`;
  - `test_http_requires_auth` (401 or 403 as in Task 3);
  - `test_consult_token_session_links_inbound_task`;
  - `test_unknown_agent_404`;
  - `test_core_does_not_import_mcp` (in a subprocess: `import a2agw, a2agw.serve.host, a2agw.config` leaves `"mcp" not in sys.modules` when MCP is not configured).
  - `test_cli.py::test_mcp_command_refuses_unlisted_agent`.
- [ ] **Step 2:** Run `uv run pytest tests/gateway/test_mcp_server.py -q`. Expected: FAIL.
- [ ] **Step 3:** Implement the server, the mount, the CLI command and the config.
- [ ] **Step 4:** Add `tests/integration/test_mcp_stdio.py::test_stdio_mcp_session_consults_partner`. It spawns `a2agw mcp` with a temp config whose partner is served by a local uvicorn on an ephemeral port, or by `card_file` plus an in-process app if simpler, through the `mcp` stdio client.
- [ ] **Step 5:** Run the full suite and ruff, then commit with `feat(gateway): outbound MCP server (stdio and streamable HTTP)`.

---

### Task 5: Adapter contract kit and the OpenAI Agents SDK adapter

**Files:**
- Create: `tests/adapters/contract.py`, `src/a2agw/adapters/openai_agents.py`, `examples/adapters/openai_agents_example.py`.
- Modify: `pyproject.toml` (extra `openai = ["openai-agents>=0.24"]`, added to `all`), `README.md` (an adapter section).
- Test: `tests/adapters/test_openai_agents.py`.

**Interfaces:**
- Produces (the contract kit, used by Tasks 6–10):
  - `async drive(adapter: InboundAdapter, text: str, *, context_id: str = "c1", task_id: str = "t1") -> list[AgentEvent]`.
  - `assert_text_stream(events, expected_text)`: chunks concatenate to the text, and exactly one final `last=True` or `Done`.
  - `async assert_multi_turn(adapter, first: str, second: str, expect_memory: str)`: the second turn on the same `context_id` sees the first.
  - `async assert_failure_maps(adapter_raising) -> None`: the exception propagates, or a `Failed` event is produced. Either is valid, because the executor fails the task.
  - `async assert_cancellable(adapter, *, within_s=2.0)`: cancelling the run's task ends it promptly.
  - `FakePartnerClient`, which records `consult` calls and returns envelopes, plus `assert_projection(tools: list[Any], call: Callable[[Any, dict], Awaitable[Any]])`: calling the first projected tool with `{"message": "hi"}` reaches `FakePartnerClient.consult` and returns the JSON envelope.
- Produces (OpenAI):
  - `OpenAIAgentsAdapter(agent: agents.Agent, *, session_factory: Callable[[str], Session] | None = None, durable_sessions: bool = False, max_turns: int = 10)`.
  - `as_openai_tools(tools: list[PartnerTool], client: PartnerClient) -> list[agents.FunctionTool]`.

**Decisions:**
- **Inbound:** `Runner.run_streamed(agent, ctx.text, session=session_factory(ctx.context_id) if session_factory else None, max_turns=max_turns)`. The default `session_factory` is an in-memory session keyed by `context_id`.
  - Map text deltas to the streamed "output" artifact.
  - Usage from the run result becomes `Usage`.
  - A tool-call event becomes `Status("calling <tool>")`.
- **Projection:** `FunctionTool(name, description + UNTRUSTED_NOTE, params_json_schema=<strict-compatible copy of tool.parameters>, on_invoke_tool=...)`, which calls `invoke` and returns the JSON envelope string.
  - Verify the installed version's `FunctionTool` fields and strict-schema rules, and record them in the ledger's context notes.
- **Fake model:** a test `Model` implementation, following `agents.models.interface.Model`, that streams scripted text and can emit one tool call.

- [ ] **Step 1:** Write the contract kit and the failing `test_openai_agents.py`:
  - `test_streams_text`;
  - `test_multi_turn_session_memory`;
  - `test_tool_call_reaches_partner_client` (the scripted fake emits a call to the projected partner tool);
  - `test_usage_reported`;
  - `test_cancellable`;
  - `test_missing_extra_message` (mock `ImportError`, and check that the message names `a2a-gateway[openai]`).
- [ ] **Step 2:** Run `uv run pytest tests/adapters/test_openai_agents.py -q`. Expected: FAIL.
- [ ] **Step 3:** Implement. Add the extra and a dev-group entry so `uv run pytest` installs it.
- [ ] **Step 4:** Make the example runnable with the fake model, with a comment on swapping in a real model. Then run the full suite and ruff.
- [ ] **Step 5:** Commit with `feat(adapters): OpenAI Agents SDK adapter and adapter contract kit`.

---

### Task 6: Claude Agent SDK adapter

**Files:**
- Create: `src/a2agw/adapters/claude_agent.py`, `examples/adapters/claude_agent_example.py`.
- Modify: `pyproject.toml` (extra `claude = ["claude-agent-sdk>=0.2.174"]`), `README.md`.
- Test: `tests/adapters/test_claude_agent.py`.

**Interfaces:**
- Consumes: the contract kit (Task 5).
- Produces:
  - `ClaudeAgentAdapter(options: ClaudeAgentOptions | None = None, *, query: Callable[..., AsyncIterator[Any]] | None = None, durable_sessions: bool = False)`. `query` defaults to `claude_agent_sdk.query` and is the test seam.
  - `as_claude_tools(tools: list[PartnerTool], client: PartnerClient, *, server_name: str = "a2a_partners") -> McpSdkServerConfig`, built with the SDK's `create_sdk_mcp_server` and `@tool` (in process, no network).

**Decisions:**
- **Session continuity:** keep a map `context_id -> session_id` from the SDK's result or system messages, and resume with `options.resume=session_id` on the next turn. With `durable_sessions=True`, the map is persisted in the host store. Otherwise it lives in memory and is bounded by an LRU of 10,000 entries.
- **Event mapping:**
  - `AssistantMessage` text blocks map to text chunks.
  - `ResultMessage` maps to `Done`, plus `Usage` from its usage and cost fields.
  - An error result maps to `Failed("agent error")`.
- **Never** run the real Claude Code CLI in tests: inject `query`. The example documents that a real run needs the `claude` CLI and `ANTHROPIC_API_KEY`.

- [ ] **Step 1: Write the failing tests** with a fake `query` yielding SDK message dataclasses:
  - `test_streams_text`;
  - `test_resume_uses_session_id_per_context`;
  - `test_result_usage_and_cost`;
  - `test_error_result_fails`;
  - `test_tools_server_call_reaches_partner_client` (call the SDK tool handler directly);
  - `test_cancellable`.
- [ ] **Step 2:** Run the tests; they must FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the tests; they must PASS. Then run the full suite and ruff.
- [ ] **Step 5:** Commit with `feat(adapters): Claude Agent SDK adapter`.

---

### Task 7: Google ADK adapter

**Files:**
- Create: `src/a2agw/adapters/adk.py`, `examples/adapters/adk_example.py`.
- Modify: `pyproject.toml` (extra `adk = ["google-adk>=2.13"]`), `README.md`.
- Test: `tests/adapters/test_adk.py`.

**Interfaces:**
- Produces:
  - `AdkAdapter(agent: BaseAgent, *, app_name: str = "a2agw", session_service: BaseSessionService | None = None, durable_sessions: bool = False)`.
  - `as_adk_tools(tools, client) -> list[FunctionTool]`.

**Decisions:**
- **Run:** `Runner(agent=..., app_name=..., session_service=...).run_async(user_id=<principal id or "anonymous">, session_id=ctx.context_id, new_message=Content(role="user", parts=[Part(text=ctx.text)]))`. The session is created on first use.
- **Event mapping:** partial text maps to chunks, the final response to `Done`, and `usage_metadata` to `Usage`.
- **Default session service:** `InMemorySessionService`.
- **Projection:** a `FunctionTool` with an explicit declaration from `tool.parameters`. Verify how ADK accepts a JSON schema in the installed version, and record it in the ledger's context notes.
- **Fake model:** a `BaseLlm` subclass with scripted responses, including one function call.

- [ ] **Step 1: Write the failing tests:**
  - `test_streams_text`;
  - `test_session_per_context`;
  - `test_function_call_reaches_partner_client`;
  - `test_usage_reported`;
  - `test_cancellable`.
- [ ] **Step 2:** Run the tests; they must FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the tests; they must PASS. Then run the full suite and ruff.
- [ ] **Step 5:** Commit with `feat(adapters): Google ADK adapter`.

---

### Task 8: AG2 adapter

**Files:**
- Create: `src/a2agw/adapters/ag2.py`, `examples/adapters/ag2_example.py`.
- Modify: `pyproject.toml` (extra `ag2 = ["ag2>=1.2"]`), `README.md`.
- Test: `tests/adapters/test_ag2.py`.

**Interfaces:**
- Produces:
  - `AG2Adapter(agent: ConversableAgent, *, history_limit: int = 50, durable_sessions: bool = False)`.
  - `register_ag2_tools(tools, client, *, caller: ConversableAgent, executor: ConversableAgent) -> None`, which uses AG2's function registration so the LLM agent proposes the call and the executor runs it.

**Decisions:**
- **Run:** call `agent.a_generate_reply(messages=history + [{"role": "user", "content": ctx.text}])`, with history kept per `context_id` in memory (bounded by `history_limit` messages and an LRU of 10,000 contexts). The reply becomes `Done(text)`; the result is not streamed (AG2 does not stream replies here).
- **Tests:** use an agent with `llm_config=False` and a registered reply function, plus a function-calling path using a scripted reply.

- [ ] **Step 1: Write the failing tests:**
  - `test_reply_completes`;
  - `test_history_per_context`;
  - `test_registered_tool_reaches_partner_client`;
  - `test_cancellable`.
- [ ] **Step 2:** Run the tests; they must FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the tests; they must PASS. Then run the full suite and ruff.
- [ ] **Step 5:** Commit with `feat(adapters): AG2 adapter`.

---

### Task 9: LlamaIndex adapter

**Files:**
- Create: `src/a2agw/adapters/llamaindex.py`, `examples/adapters/llamaindex_example.py`.
- Modify: `pyproject.toml` (extra `llamaindex = ["llama-index-core>=0.14.25"]`), `README.md`.
- Test: `tests/adapters/test_llamaindex.py`.

**Interfaces:**
- Produces:
  - `LlamaIndexAdapter(workflow: Workflow, *, durable_sessions: bool = False)`, for a `FunctionAgent` or `AgentWorkflow`.
  - `as_llamaindex_tools(tools, client) -> list[FunctionTool]`.

**Decisions:**
- **Run:** `handler = workflow.run(user_msg=ctx.text, ctx=<Context per context_id>)`. Stream `AgentStream` deltas as chunks; the final output becomes `Done`.
- **Contexts:** kept per `context_id`, in memory with an LRU of 10,000.
- **Projection:** `FunctionTool.from_defaults(async_fn=..., name=..., description=..., fn_schema=<pydantic model built from tool.parameters>)`.
- **Fake model:** `llama_index.core.llms.MockLLM`, or a scripted `FunctionCallingLLM` subclass for the tool-call test.

- [ ] **Step 1: Write the failing tests:**
  - `test_streams_text`;
  - `test_context_memory`;
  - `test_tool_call_reaches_partner_client`;
  - `test_cancellable`.
- [ ] **Step 2:** Run the tests; they must FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the tests; they must PASS. Then run the full suite and ruff.
- [ ] **Step 5:** Commit with `feat(adapters): LlamaIndex adapter`.

---

### Task 10: CrewAI adapter (separate environment)

**Files:**
- Create: `src/a2agw/adapters/crewai.py`, `examples/adapters/crewai_example.py`, `scripts/test-crewai.sh`.
- Modify:
  - `pyproject.toml`:
    - extra `crewai = ["crewai>=1.15"]`;
    - `[tool.uv] conflicts = [[{extra = "crewai"}, {extra = "mcp"}], [{extra = "crewai"}, {extra = "openai"}]]`;
    - a dependency group `crewai-test = ["pytest", "pytest-asyncio", "crewai>=1.15"]` declared conflicting with group `dev`.
  - `README.md`, including the note on why CrewAI runs in its own environment.
- Test: `tests/adapters/test_crewai.py`. It starts with `pytest.importorskip("crewai")`, so the main suite skips it, and the CrewAI script runs it.

**Interfaces:**
- Produces:
  - `CrewAIAdapter(crew: Crew, *, input_key: str = "input", durable_sessions: bool = False)`.
  - `as_crewai_tools(tools, client) -> list[BaseTool]`.

**Decisions:**
- **Run:** `await crew.kickoff_async(inputs={input_key: ctx.text, "context_id": ctx.context_id})`. The result becomes `Done(str(result))`. Token usage from `crew.usage_metrics`, when present, becomes `Usage`.
- **Projection:** a `BaseTool` subclass with an `args_schema` built from `tool.parameters`. `_run` and `_arun` call `invoke`.
- **Fake model:** a `BaseLLM` subclass with scripted output.
- **Test command:** `scripts/test-crewai.sh` runs `uv run --no-default-groups --group crewai-test pytest tests/adapters/test_crewai.py -q -W error`. If uv cannot express the group conflict, the fallback is `uv run --isolated --with 'crewai>=1.15' --with pytest --with pytest-asyncio --with-editable . pytest ...`; record the choice in the ledger.

- [ ] **Step 1: Write the failing tests:**
  - `test_kickoff_completes`;
  - `test_usage_metrics_reported`;
  - `test_tool_reaches_partner_client`;
  - `test_cancellable`.
- [ ] **Step 2:** Run `scripts/test-crewai.sh`; it must FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the script; it must PASS. The main suite stays green with CrewAI skipped.
- [ ] **Step 5:** Commit with `feat(adapters): CrewAI adapter (isolated environment)`.

---

### Task 11: Docker image

**Files:**
- Create: `Dockerfile`, `.dockerignore`, `examples/docker/a2agw.yaml`, `examples/docker/compose.yaml`.
- Modify: `README.md` (a Docker section).
- Test: `tests/docker/test_image.py`, marked `docker` and skipped when `docker info` fails or `A2AGW_DOCKER_TESTS` is unset.

**Decisions:**
- **Build:** a multi-stage build on `python:3.12-slim`.
  - The build stage uses `uv` (pinned version) to build a wheel and install `a2a-gateway[postgres,mcp]` into `/opt/venv`.
  - The runtime stage copies only the venv. It runs as user `a2agw`, uid 10001, with no shell login, `WORKDIR /config`, and `EXPOSE 8000`.
  - `ENTRYPOINT ["a2agw"]`, `CMD ["serve", "-c", "/config/a2agw.yaml", "--host", "0.0.0.0", "--port", "8000"]`.
  - `HEALTHCHECK` calls `GET /a2agw/admin/healthz` with Python's `urllib`; there is no curl in the image.
- **Build argument:** `EXTRAS` (default `postgres,mcp`), so users can add adapters.
- **Compose example:** the gateway plus Postgres plus the Node coder from Task 12, with secrets taken from the environment.

- [ ] **Step 1: Write the failing tests:**
  - `test_image_builds_and_serves_card`: build, run with `examples/docker/a2agw.yaml` mounted, wait for health, and `GET /agents/echo/.well-known/agent-card.json` returns 200;
  - `test_runs_as_non_root`: `docker run --entrypoint id` prints uid 10001.
- [ ] **Step 2:** Run `A2AGW_DOCKER_TESTS=1 uv run pytest tests/docker -q`. Expected: FAIL (no Dockerfile).
- [ ] **Step 3:** Write the Dockerfile and the compose example.
- [ ] **Step 4:** Run the tests; they must PASS. Then run the full suite: the docker tests are skipped by default.
- [ ] **Step 5:** Commit with `feat: docker image and compose example`.

---

### Task 12: "Done when" demo, docs and conformance

**Files:**
- Create:
  - `examples/node_coder/agent.mjs`: Node 24, standard library only (`node:http` and `node:crypto`).
  - `examples/node_coder/README.md`.
  - `examples/mcp_client/client.py`.
- Modify:
  - `examples/software_team/*`: add the external `coder` agent and the MCP client to the run.
  - `README.md`: the sidecar section, the roadmap, and Known limitations.
  - `docs/sidecar.md`: completed.
  - `docs/conformance.md`: re-run the TCK.
- Test: `tests/integration/test_phase3_demo.py`.

**Decisions:**
- **The Node coder** is a webhook agent at `POST /a2agw/invoke`.
  - It verifies the HMAC signature and timestamp, rejecting a skew over 300 s with 401.
  - It streams NDJSON: `status`, then text chunks, then `done`.
  - While running, it consults the `security` partner through the REST API with its consult token, which proves a linked hop from a non-Python agent.
- **The MCP client** is an MCP-only agent: a Python `mcp` client standing in for Claude Code or Cursor.
  - It connects to `/a2agw/mcp/pm-desk` with an API key scoped `a2agw:sidecar`.
  - It lists tools, consults `pm`, and waits on the handle with `a2a_wait`.
- **Demo flow:** the MCP client asks the PM. The PM delegates to the architect and to the Node coder, and the coder consults security. All of it lands in one trace and one audit chain, which the demo verifies.
- **Test:** `test_phase3_demo` is skipped when `node` is not on PATH. It runs the demo in process (the Node agent as a subprocess on an ephemeral port) and asserts:
  - the MCP client got a completed envelope;
  - the Node agent's partner call has `inbound_task_id` set (linked);
  - one trace id spans all hops;
  - `audit verify` is ok.
- **Deferred (§11a.7 "may"):** the optional authenticated webhook receiver for partner push notifications. It goes in README Known limitations as Phase 4+.

- [ ] **Step 1:** Write the failing `test_phase3_demo.py` as described.
- [ ] **Step 2:** Run it; it must FAIL.
- [ ] **Step 3:** Write the Node agent, the MCP client and the demo wiring.
- [ ] **Step 4:** Run the test; it must PASS. Re-run the TCK; the MUST level must show 0 failures. Update `docs/conformance.md` and the README.
- [ ] **Step 5:** Run the full suite, the CrewAI script and ruff.
- [ ] **Step 6:** Commit with `feat: phase 3 demo (Node webhook agent and MCP-only agent) and docs`.

---

## Self-review notes

- **Spec coverage (§9, Phase 3 row):**

  | Requirement | Task(s) |
  |---|---|
  | Sidecar service | 1, 2, 3, 4 (served by the existing `a2agw serve`) |
  | MCP server outbound | 4 |
  | HTTP webhook inbound contract | 1, plus stdio in 2 (§7.7 "or stdio") |
  | CrewAI, OpenAI Agents, Claude Agent SDK, ADK, AG2 and LlamaIndex adapters | 10, 5, 6, 7, 8, 9 |
  | Docker image | 11 |
  | Done when | 12 |
  | §7.7 REST API (`POST /partners/{id}/messages`) | 3 (mounted under `/a2agw/v1`) |
  | §11a.7 push receiver | Deferred (the spec says "may") |

- **Deviations, each recorded as a ruling when executed:**
  - The REST prefix is `/a2agw/v1`.
  - The CrewAI adapter runs in its own environment because of hard pins.
  - The spec's demo roles (architect on OpenAI Agents, coder on the Claude SDK, reviewer on CrewAI) are covered by per-adapter examples instead of one process. CrewAI cannot share an environment with OpenAI Agents, and Phase 3's "done when" names the non-Python and MCP-only agents.
- **Type consistency:**
  - `ConsultGrant` is defined in Task 1 and filled in Task 3.
  - `Binding`, `ConsultTokens` and `sidecar_owner` come from Task 3 and are used by Task 4.
  - The contract kit from Task 5 is used by Tasks 6–10.
