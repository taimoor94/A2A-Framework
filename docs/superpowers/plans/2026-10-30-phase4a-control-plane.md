# Phase 4a (Control Plane) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the backend that operators will run the Console on: a control-plane service that owns the partner catalogue, policies, users and roles. Each gateway connects out to it, receives its partners and policy from it, reports what happens, and carries out operator actions. Every operation the Console (§7.10) needs is available through one authenticated, role-checked API, across many gateways.

**Architecture:**
- **New package `a2agw.control`**, a FastAPI service behind a new `control` extra. It stores its state with SQLAlchemy Core on SQLite (development and tests) or PostgreSQL (production), using the same `create_engine` and `retry_ddl` helpers as the gateway. It has two APIs:
  - `/api/v1`, for people (the Console) and automation;
  - `/cp/v1`, for gateways.
- **Gateways connect outbound** (spec §7.10: "Gateways never need to be reachable from the control plane"). A new connector, `a2agw.ops.cp_client`, holds one SSE stream open to the control plane. The stream carries the versioned *desired state* (the gateway's partners and policy) and *commands* (cancel a task, answer a prompt, and so on). On a separate connection, the connector POSTs batched reports: bus events, audit rows, health and metrics, command results, and the version it has applied.
- **On the gateway side, one module, `a2agw.ops.actions`,** holds every write operation (approve a partner, cancel a task, set the policy, and so on). Three callers share it: the gateway's own admin API, the CLI and the connector's commands. One implementation means one audit trail.
- **The gateway keeps its own defences.** A partner record from the control plane is still SSRF-checked and signature-verified locally, and a card change is still quarantined locally. The control plane decides policy and the catalogue; it cannot switch off a gateway's local safety checks.

**Tech Stack:**
- Python 3.12 (supports 3.11 and later), uv, Starlette, SQLAlchemy Core 2.x, `httpx<0.29`, `pyjwt[crypto]`, pydantic v2, OpenTelemetry.
- New: `fastapi>=0.115,<1` (the `control` extra only).
- Tests: pytest, `respx` (a fake OIDC provider), and httpx `ASGITransport` (the control plane and gateways run in-process).

**Spec:** `docs/superpowers/specs/2026-10-25-a2a-gateway-framework-design.md`. Phase 4 is described in §7.8, §7.10, §7.5, §7.6, §9 and §11/§11a. The spec is binding and this plan argues from it.

**Phase 4 is three plans,** each producing working software on its own:
- **4a (this plan):** the control plane and the gateway side of it.
- **4b:** the Console web app (React + TypeScript + Vite, shadcn/ui + Tailwind, TanStack Query, React Flow, ECharts), built against the 4a OpenAPI schema.
- **4c:** the Helm chart and the operations docs.

The spec's Phase 4 "done when" is reached at the end of 4b. The 4a "done when" is below.

## Global Constraints

- The core does not import FastAPI. `fastapi` is only in the new `control` extra and is imported only under `a2agw.control`. A missing extra raises `ImportError` naming `pip install 'a2a-gateway[control]'`. The gateway connector (`a2agw.ops.cp_client`) uses only httpx, so a gateway needs no new dependency.
- Dependencies: `a2a-sdk>=1.2.3,<2`, `httpx>=0.28,<0.29`, `fastapi>=0.115,<1`. No ORM models, no alembic. Tables are SQLAlchemy Core `Table`s on a module-private `MetaData`, created and migrated through `retry_ddl` (the `_ADDED_COLUMNS` pattern for new columns).
- SQLite and PostgreSQL both work for both services. Every new store test also runs against Postgres through the existing `postgres` marker.
- Security is fail-closed:
  - Secrets (gateway tokens, API keys, session ids, the OIDC client secret) come only from `*_env` or files. They are stored only as SHA-256 digests and never appear in logs, errors, audit rows, events or API responses. The single exception is the one creation response that shows a new token or key once.
  - Every write in either service is audited.
  - Every `/api/v1` route has a declared permission, enforced by one dependency. A route without one fails a test.
  - A gateway can read only its own desired state and commands, and can post only its own reports. Its identity comes from its token, never from the request body.
  - All outbound HTTP from the control plane (card fetches) goes through `a2agw.consult.guarded_net`.
- Gateway behaviour without `control_plane:` in its config is unchanged. The public API is additive, and the A2A TCK MUST level stays at 0 failures.
- Every test is deterministic: no real network, no real identity provider, and fake clocks where time matters.
- Test gate: `uv run pytest -q -W error` passes when run alone, `uv run ruff check` is clean, and `scripts/test-crewai.sh` is green.
- "Done when" (4a): **one end-to-end test runs a control plane and two gateways in-process and does every §7.10 Console operation through `/api/v1`, with role checks. The operations are:**
  - register, approve, quarantine and reject a partner, and see the card diff;
  - assign partners and a policy to the gateways, and run a policy dry-run;
  - see tasks, a cross-agent timeline and the topology;
  - cancel a task and answer an `input-required` prompt;
  - read and export the audit log;
  - manage gateways, users and API keys.

## Review Focus

1. **The control plane is unreachable or restarts.** Every gateway keeps serving with the partners and policy it last applied, including across its own restart (fail static). It reconnects with capped, jittered back-off, then resends the reports that weren't acknowledged, without duplicates. Tests: Task 7.
2. **Desired state arrives out of order, or a gateway rejects it.** A version older than or equal to the applied one is never applied. A state the gateway refuses (invalid policy, a card that fails local SSRF or signature checks) leaves the previous state in force, and the refusal and its reason show on the control plane. Tests: Tasks 6, 7 and 9.
3. **A leaked or revoked gateway token.** Revocation ends that gateway's open stream within one keepalive interval, and every later request gets 401. Other gateways are unaffected. A valid token can never read another gateway's state or post as another gateway. Tests: Task 6.
4. **An operator action aimed at an offline or slow gateway.** The API answers within its wait bound, with the command still pending. The command expires after its TTL, and an expired command is never delivered later. Tests: Tasks 6 and 11.
5. **A flood or malformed report from a gateway** (huge batches, unknown event kinds, bad JSON). It is rejected or truncated with a bounded body size and counted. It never stalls ingestion for other gateways, and never lands unvalidated text in the audit log. Tests: Task 6.

---

## File Structure

| File | Responsibility |
|---|---|
| `src/a2agw/ops/actions.py` | Gateway write operations, shared by the admin API, the CLI and the connector. |
| `src/a2agw/ops/metrics.py` | `GatewayMetrics`: in-process counters and latency summaries, plus optional OTel instruments. |
| `src/a2agw/ops/cp_client.py` | `ControlPlaneConnector`: the stream, applying state, reports, commands and the fail-static cache. |
| `src/a2agw/consult/carddiff.py` | `card_diff(old, new) -> list[CardChange]`. |
| `src/a2agw/control/__init__.py` | Package marker; the import guard for the `control` extra. |
| `src/a2agw/control/settings.py` | `ControlSettings` (YAML plus `${VAR}`), loaded like the gateway config. |
| `src/a2agw/control/store.py` | Every `cp_*` table and `ControlStore.initialize()`. |
| `src/a2agw/control/app.py` | `create_app(settings) -> FastAPI`: routers, error handlers, lifespan. |
| `src/a2agw/control/authn.py` | API keys, sessions, the OIDC BFF flow and CSRF. |
| `src/a2agw/control/rbac.py` | Roles, `Permission`, the permission table and `require(permission)`. |
| `src/a2agw/control/channel.py` | `/cp/v1`: gateway auth, the stream, report ingestion, desired state and commands. |
| `src/a2agw/control/catalogue.py` | Partner registration, versions, diffs, approval and assignment. |
| `src/a2agw/control/policies.py` | Policy versions, validation, assignment and dry-run. |
| `src/a2agw/control/views.py` | Read APIs: overview, agents, tasks, timeline, topology, audit and export. |
| `src/a2agw/control/operations.py` | Operator actions turned into commands, and command status. |
| `src/a2agw/control/admin.py` | Gateways, users, API keys and settings. |
| `docs/control-plane.md` | Operator reference: deployment, gateway enrollment, roles, the APIs and failure behaviour. |

---

### Task 1: Gateway write operations, card diff and live policy

**Files:**
- Create: `src/a2agw/ops/actions.py`, `src/a2agw/consult/carddiff.py`.
- Modify:
  - `src/a2agw/consult/registry.py`: add `remove(id)` and `reject(id)`.
  - `src/a2agw/serve/host.py`: add `set_policy`, and the publishers for `partner.state` and `security.denied`.
  - `src/a2agw/ops/audit.py`: new `Action`s and `DETAIL_KEYS`.
  - `src/a2agw/ops/bus.py`: event kinds.
  - `src/a2agw/cli.py`: `partners remove|reject`.
- Test: `tests/consult/test_carddiff.py`, `tests/consult/test_registry.py`, `tests/ops/test_actions.py`, `tests/serve/test_host.py`, `tests/test_cli.py`.

**Interfaces:**
- Consumes:
  - `PartnerRegistry` mutators (`add_from_url`, `add_from_card`, `approve`, `disable`, `enable`, `update_settings`) and `acting_as(actor)`;
  - `host.reload_partners`, `host.reap`, `host.policy` and `host.bus`.
- Produces:
  - `card_diff(old: dict, new: dict) -> list[CardChange]`, where `CardChange` is a frozen dataclass `{path: str, kind: Literal["added","removed","changed"], old: Any, new: Any, significant: bool}`.
    - `path` is dotted, with list items keyed by `id` when present (`skills[code-review].description`), otherwise by index.
    - `significant` follows the registry's `_significant_differs` rule: top-level keys outside `COSMETIC_FIELDS | {"signatures"}`.
  - `PartnerRegistry.remove(id) -> None`: raises `KeyError`; emits `removed`.
  - `PartnerRegistry.reject(id) -> None`: drops `pending_card`/`pending_key_id`, sets `status="disabled"` and emits `rejected`. It raises `ValueError` when nothing is pending.
  - `AgentHost.set_policy(policy: Policy | None, *, actor: str, source: Literal["file","control_plane","admin"]) -> None`:
    - swaps `host.policy.policy` on the shared engine, or creates the engine when it was `None`;
    - `None` restores no-policy;
    - audits `policy.update` with `detail.reason=source`.
  - `a2agw.ops.actions`. Every function takes `host: AgentHost` and keyword `actor: str` and returns a JSON-able dict:
    - `add_partner(host, *, id, card_url | card, tier, credential_ref=None, tls_ref=None, tags=())`;
    - `approve_partner(host, id, *, expected_hash)`, `reject_partner(host, id)`, `disable_partner(host, id)`, `enable_partner(host, id)`;
    - `remove_partner(host, id, *, force=False)`: 409 semantics through `PartnersInUse`, as `reload_partners`;
    - `refresh_partner(host, id)`;
    - `update_partner(host, id, **settings)`;
    - `partner_detail(host, id)`: `{record fields except credential secrets, card, pending_card, diff: [CardChange as dict]}`;
    - `cancel_task(host, agent_id, task_id)`, `answer_task(host, agent_id, task_id, text)`, `task_detail(host, agent_id, task_id)` (Task 2 fills these in);
    - `reap(host, agent_id, *, confirm, force)` and `set_policy(host, policy_doc: dict)`.
  - New audit `Action`s: `partner.reject`, `policy.update`, `task.cancel`, `task.answer`, `cp.connect`, `cp.apply`, `cp.reject`, `cp.command`. New `DETAIL_KEYS`: `version`, `command`, `source`, `hash`.
  - Bus events now published:
    - `partner.state` (`data={partner_id, status, event}`) from the registry listener;
    - `security.denied` (`data={reason, rule?, principal_kind}`) wherever `authz.deny`, `egress.deny` or `sidecar.denied` is audited. It never carries principal ids or message text.

**Decisions:**
- **Removal with open partner tasks:** `remove_partner` without `force` raises `PartnersInUse`. With `force`, it cancels the open handles through the cascade path first (this is the existing `reload_partners(force=True)` behaviour).
- **The policy swap is atomic:** consumers read `engine.policy` once per decision. Add a test that a decision in flight uses one consistent policy.

- [ ] **Step 1: Write the failing tests.**
  - `test_carddiff.py`:
    - `test_skill_description_change_is_significant_and_keyed_by_id`;
    - `test_version_change_is_cosmetic`;
    - `test_identical_cards_no_changes`;
    - `test_added_and_removed_skills`.
  - `test_registry.py`:
    - `test_remove_partner_emits_removed_and_persists`;
    - `test_reject_clears_pending_and_disables`;
    - `test_reject_without_pending_raises`.
  - `test_actions.py`:
    - `test_every_action_audits_with_actor`, parametrized over each action;
    - `test_partner_detail_has_diff_and_no_secrets` (no `credential_ref` value, only the ref name);
    - `test_remove_with_open_handles_needs_force`.
  - `test_host.py`:
    - `test_set_policy_swaps_live_and_audits`;
    - `test_set_policy_none_restores_open`;
    - `test_partner_state_and_security_denied_are_published` (no principal id in the payload).
  - `test_cli.py::test_partners_remove_and_reject`.
- [ ] **Step 2:** Run `uv run pytest tests/consult tests/ops tests/serve/test_host.py -q`. Expected: FAIL.
- [ ] **Step 3:** Implement. The existing admin `POST partners/reload` and `POST tasks/reap` handlers and the CLI partner commands call `a2agw.ops.actions`; their responses stay unchanged.
- [ ] **Step 4:** Run the full suite and ruff. Commit with `feat(ops): shared gateway actions, card diff, live policy`.

---

### Task 2: Gateway admin API: task detail, cancel, answer, partner and policy writes

**Files:**
- Modify:
  - `src/a2agw/ops/admin.py`: the new routes.
  - `src/a2agw/serve/store.py`: a `trace_id` column on `a2agw_task_index` via `_ADDED_COLUMNS`.
  - `src/a2agw/serve/executor.py`: record the trace id; add it to `task.state` events.
  - `src/a2agw/ops/actions.py`: the task functions.
  - `README.md`: the admin table.
- Test: `tests/ops/test_admin_writes.py`, `tests/serve/test_store.py`, `tests/integration/test_admin_answer.py`.

**Interfaces:**
- Consumes: Task 1's `actions`, the per-agent SDK task stores (`task_store_for`), the request handlers (`host.handlers[agent_id]`) and `OutboundHandleStore.by_inbound`.
- Produces: new routes under `/a2agw/admin`. All of them need `a2agw:admin`. POSTs also need `X-A2AGW-Admin: 1`. Every write is audited.

  | Method | Path | Body | Response |
  |---|---|---|---|
  | GET | `tasks/{agent_id}/{task_id}` | none | `{task: {id, context_id, state, owner, updated_at, trace_id, status_message, history: [...], artifacts: [...]}, partner_tasks: [handle rows], pending_prompt: str\|null}` |
  | POST | `tasks/{agent_id}/{task_id}/cancel` | none | `{state}`; 409 `{"error":"task is final"}` |
  | POST | `tasks/{agent_id}/{task_id}/answer` | `{"text": str}` (≤ 32 KiB) | `{state}`; 409 `{"error":"task is not waiting for input"}` |
  | GET | `partners/{id}` | none | `actions.partner_detail` |
  | POST | `partners` | `{id, card_url \| card, tier, credential_ref?, tls_ref?, tags?}` | partner detail; 409 duplicate; 422 card error |
  | POST | `partners/{id}/approve` | `{"expected_hash": str}` | partner detail; 409 on a hash mismatch |
  | POST | `partners/{id}/{reject\|disable\|enable\|refresh}` | none | partner detail |
  | DELETE | `partners/{id}` | query `force` | `{removed: id}`; 409 with open handles |
  | GET | `policy` | none | `{managed: bool, source, policy: dict\|null}` |
  | PUT | `policy` | a policy document | `{policy}`; 409 `{"error":"policy is managed by the control plane"}` when managed; 422 `{"error":"invalid policy","fields":[dotted paths]}` |

  - **History and artifacts** are capped at the last 50 messages and 50 artifacts. File parts are listed by name, MIME type and size only, never their bytes or URLs.
  - **A 404 does not distinguish** an unknown agent from an unknown task (spec §7.5: "doesn't reveal whether a task exists").

**Decisions:**
- **Answer:**
  - The operator's text is sent into the task as a new user message through the agent's request handler, with a server call context whose user is the task's owner principal (`Principal.from_id(owner)`), so ownership checks pass and the task stays the owner's.
  - The message carries the metadata `{"a2agw.answered_by": "<actor>"}`, so the agent and the history show who answered.
  - Audited as `task.answer` with actor = the admin principal.
  - Allowed only in `TASK_STATE_INPUT_REQUIRED`. `AUTH_REQUIRED` is refused, because an operator must not supply someone else's credentials.
- **Cancel:** goes through the handler's cancel path, so the partner-task cascade runs. Audited as `task.cancel`.
- **`trace_id`:** the 32-hex trace id of the inbound span, nullable, set when the task index row is first recorded. The `task.state` event data gains `trace_id`.

- [ ] **Step 1: Write the failing tests.**
  - `test_admin_writes.py`:
    - `test_task_detail_shape_and_caps`;
    - `test_task_detail_404_does_not_leak_existence`;
    - `test_cancel_running_task_cascades_to_partner_tasks`;
    - `test_cancel_final_task_409`;
    - `test_partner_crud_round_trip` (add, get with diff, approve with hash, reject, disable, enable, delete);
    - `test_approve_wrong_hash_409`;
    - `test_policy_put_validates_and_swaps`;
    - `test_policy_put_409_when_managed`;
    - `test_writes_need_csrf_header_and_admin_scope`;
    - `test_every_write_audited`.
  - `test_admin_answer.py`:
    - `test_operator_answer_resumes_input_required_task` (a LangGraph-style fake that asks, then completes with the answer);
    - `test_answer_refused_for_auth_required`;
    - `test_answer_metadata_names_operator`.
  - `test_store.py`:
    - `test_trace_id_column_added_to_existing_table` (SQLite and Postgres);
    - `test_task_state_event_carries_trace_id`.
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3:** Implement. Update the README admin table, which should now list all routes, including `/audit`, `/audit/verify` and `/push`.
- [ ] **Step 4:** Run the full suite, the TCK (`scripts/run_tck.sh`, MUST 0 failures) and ruff. Commit with `feat(admin): task detail, cancel, answer; partner and policy writes`.

---

### Task 3: Gateway metrics

**Files:**
- Create: `src/a2agw/ops/metrics.py`.
- Modify:
  - `src/a2agw/serve/host.py` (owns `host.metrics`);
  - `src/a2agw/consult/client.py` and `src/a2agw/serve/executor.py` (record);
  - `src/a2agw/ops/admin.py` (`GET metrics`);
  - `src/a2agw/ops/telemetry.py` (an optional meter provider);
  - `src/a2agw/config.py` (`telemetry.metrics: bool = true`).
- Test: `tests/ops/test_metrics.py`.

**Interfaces:**
- Produces: `GatewayMetrics(clock=time.monotonic, window_s=300)` with:
  - `record_partner_call(agent_id, partner_id, state, duration_ms)`;
  - `record_task_state(agent_id, state)`;
  - `record_hop(depth)`;
  - `snapshot() -> dict`:

    ```
    {"window_s": 300,
     "partners": {pid: {"calls": int, "errors": int, "p50_ms": float, "p95_ms": float, "breaker": str, "in_flight": int}},
     "tasks_by_state": {agent_id: {STATE: int}},   # current, from the index
     "hop_depth": {"p50": int, "max": int},
     "edges": [{"from": agent_id, "to": partner_id, "calls": int, "errors": int, "p95_ms": float}]}
    ```

  - `async snapshot_with_index(index) -> dict` fills `tasks_by_state` from `TaskIndex`, adding a `count_by_state()` helper there.
  - When an OTel `MeterProvider` is configured, the same records also go to the instruments `a2agw.partner.calls` (counter, attributes partner_id/state), `a2agw.partner.duration` (histogram, ms) and `a2agw.task.transitions` (counter).
- Admin `GET /a2agw/admin/metrics` returns `snapshot_with_index`.

**Decisions:**
- **Rolling window:** errors count `state in {"failed","unavailable","rejected"}`. Percentiles come from a bounded ring per partner (at most 1024 samples) over the window. Memory is bounded by `max_partners_tracked=512`, evicting the least recently used.
- **No principal ids or message content** appear in metrics.

- [ ] **Step 1: Write the failing tests.**
  - `test_metrics_window_expires_old_samples` (fake clock);
  - `test_percentiles`;
  - `test_error_states_counted`;
  - `test_bounded_partners_lru`;
  - `test_edges_aggregate_agent_to_partner`;
  - `test_admin_metrics_route_requires_admin`;
  - `test_otel_instruments_receive_records` (an in-memory metric reader);
  - `test_no_principal_or_text_in_snapshot`.
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement and wire the recorders into the existing `_publish` points.
- [ ] **Step 4:** Run the full suite and ruff. Commit with `feat(ops): gateway metrics and admin metrics route`.

---

### Task 4: Control-plane service skeleton

**Files:**
- Create:
  - `src/a2agw/control/{__init__,settings,store,app}.py`;
  - `src/a2agw/control/cli.py`, mounted as `a2agw control` in `src/a2agw/cli.py` only when the extra is importable; otherwise the command prints the install hint.
- Modify:
  - `pyproject.toml`: the `control` extra `["fastapi>=0.115,<1"]`; add fastapi to the dev group.
  - `src/a2agw/ops/audit.py`: `AuditLog(engine, *, table_name="a2agw_audit")`.
- Test: `tests/control/conftest.py`, `tests/control/test_app.py`, `tests/control/test_settings.py`, `tests/control/test_store.py`.

**Interfaces:**
- Produces:
  - `ControlSettings` (pydantic, `extra="forbid"`), loaded by `load_control_settings(path, env=None)`. It uses the gateway's `interpolate` and inline-secret rejection. YAML keys:
    - `base_url` (required, the public URL of the control plane) and `db_url` (default `sqlite+aiosqlite:///a2agw-control.db`);
    - `oidc: {issuer, client_id, client_secret_env, scopes=["openid","profile","email"], roles_claim="groups", role_map: {group: role}}` (optional);
    - `session: {absolute_s=28800, idle_s=3600, cookie_secure=true}`;
    - `retention: {events_days=7, commands_days=7}`;
    - `limits: {report_max_bytes=1048576, report_max_items=1000, stream_keepalive_s=15}`;
    - `trust`: same shape as the gateway's `trust`, used for card signature checks.
  - `ControlStore(engine)` with `initialize()`, creating these tables (all ids are `String(64)`, timestamps `Float` epoch):
    - `cp_gateways(id PK, name unique, created_at, created_by, last_seen_at null, last_version_applied Integer default 0, status: "active"|"revoked", info_json)`;
    - `cp_gateway_tokens(digest PK, gateway_id idx, created_at, revoked_at null)`;
    - `cp_users(id PK = "oidc:<sub>", email, name, roles_json, created_at, last_login_at, disabled bool)`;
    - `cp_sessions(digest PK, user_id idx, csrf_digest, created_at, last_used_at, expires_at)`;
    - `cp_login_states(state_digest PK, nonce, code_verifier, next_path, expires_at)`, which holds a sign-in in progress for 10 minutes and is deleted at the callback;
    - `cp_api_keys(digest PK, id unique, name, role, created_by, created_at, revoked_at null, last_used_at null)`;
    - `cp_partners(id PK, card_url null, tier, credential_ref null, tls_ref null, tags_json, status: "pending"|"approved"|"quarantined"|"rejected", current_version Integer, created_at, updated_at)`;
    - `cp_partner_versions(partner_id, version, card_json, card_hash, signed_key_id null, fetched_at, approved_by null, approved_at null; PK(partner_id, version))`;
    - `cp_policies(id PK, name unique, created_at)`;
    - `cp_policy_versions(policy_id, version, doc_json, doc_hash, created_by, created_at, comment; PK(policy_id, version))`;
    - `cp_assignments(gateway_id, kind: "partner"|"policy", ref_id, ref_version null; PK(gateway_id, kind, ref_id))`;
    - `cp_desired(gateway_id PK, version Integer, doc_json, doc_hash, computed_at)`;
    - `cp_commands(id PK, gateway_id idx, kind, args_json, status: "pending"|"delivered"|"done"|"failed"|"expired", result_json null, actor, created_at, delivered_at null, finished_at null, expires_at)`;
    - `cp_events(seq PK autoincrement, gateway_id idx, ts idx, kind idx, agent_id null idx, partner_id null, task_id null idx, trace_id null idx, data_json)`;
    - `cp_gateway_audit(gateway_id, seq, row_json, ts idx; PK(gateway_id, seq))`, which copies gateway audit rows;
    - `cp_health(gateway_id PK, ts, health_json, metrics_json)`.
  - The control plane's own audit log: `AuditLog(engine, table_name="cp_audit")`, with new `Action`s `cp.login`, `cp.logout`, `cp.gateway.create`, `cp.gateway.revoke`, `cp.partner.register`, `cp.partner.approve`, `cp.partner.reject`, `cp.partner.quarantine`, `cp.assign`, `cp.policy.save`, `cp.policy.dryrun`, `cp.command`, `cp.user.update`, `cp.apikey.create`, `cp.apikey.revoke` and `cp.denied`.
  - `create_app(settings: ControlSettings, *, http: httpx.AsyncClient | None = None, clock=time.time) -> FastAPI`:
    - Its lifespan creates the engine, initializes the store and audit, and starts a maintenance task. The task expires commands, purges events and commands past retention, and recomputes desired state when assignments are dirty.
    - `GET /healthz` (public) returns `{"status":"ok"}`.
    - Errors use one shape: `{"error": "<code>", "detail": "<message>"}`. Validation errors are 422 with `fields` holding dotted paths only, never values.
    - The OpenAPI document is at `/api/openapi.json` and needs the viewer permission. The interactive docs are disabled.
  - CLI:
    - `a2agw control init [dir]` writes a commented `control.yaml`;
    - `a2agw control serve -c control.yaml [--host --port]`;
    - `a2agw control create-api-key --name N --role R -c control.yaml` prints the key once;
    - `a2agw control create-gateway --name N -c control.yaml` prints the gateway id and its token once.

- [ ] **Step 1: Write the failing tests.**
  - `test_settings.py`:
    - `test_inline_client_secret_rejected`;
    - `test_env_interpolation`;
    - `test_unknown_key_rejected_with_path`.
  - `test_store.py`:
    - `test_initialize_idempotent_concurrent`, on SQLite and Postgres;
    - `test_tables_exist`.
  - `test_app.py`:
    - `test_healthz_public`;
    - `test_error_shape`;
    - `test_openapi_requires_auth`;
    - `test_core_does_not_import_fastapi` (a subprocess imports `a2agw`, `a2agw.serve.host` and `a2agw.ops.cp_client`, then asserts `"fastapi" not in sys.modules`);
    - `test_missing_extra_message`.
  - `tests/ops/test_audit.py::test_custom_table_name_chain_verifies`.
  - CLI: `test_control_init_and_create_api_key_prints_once` (the key appears in stdout once; only its digest is in the DB).
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the full suite and ruff. Commit with `feat(control): service skeleton, settings, store, CLI`.

---

### Task 5: Control-plane authentication and roles

**Files:**
- Create: `src/a2agw/control/authn.py`, `src/a2agw/control/rbac.py`.
- Modify: `src/a2agw/control/app.py`.
- Test: `tests/control/test_authn.py`, `tests/control/test_rbac.py`, `tests/control/oidc_fake.py` (a respx-backed fake provider: discovery, JWKS, token endpoint).

**Interfaces:**
- Produces:
  - `Role = Literal["viewer","operator","security","admin"]`.
  - `Permission`, a `StrEnum` with `READ`, `TASKS_OPERATE`, `PARTNERS_REGISTER`, `PARTNERS_TRUST`, `POLICY_EDIT`, `ASSIGN`, `AUDIT_READ`, `GATEWAYS_MANAGE`, `USERS_MANAGE`, `APIKEYS_MANAGE` and `SETTINGS_MANAGE`.
  - `ROLE_PERMISSIONS: dict[Role, frozenset[Permission]]`:
    - viewer: `{READ}`;
    - operator: viewer + `{TASKS_OPERATE}`;
    - security: viewer + `{PARTNERS_TRUST, POLICY_EDIT, AUDIT_READ}`;
    - admin: every permission.
    - A user with several roles gets the union of their permissions.
  - `Actor`, a frozen dataclass `{id: str, kind: Literal["user","api_key"], roles: frozenset[Role], csrf_ok: bool}`.
  - `require(permission: Permission)`, a FastAPI dependency returning `Actor`:
    - no credentials: 401;
    - a missing permission: 403, audited as `cp.denied` with `detail.reason=permission`;
    - a session-authenticated non-GET without a valid CSRF token: 403 `{"error":"csrf"}`.
  - Every route is registered through `route(method, path, permission)` or `public(...)`. `ROUTE_PERMISSIONS` lists them for the matrix test.
  - Routes:
    - `GET /auth/login?next=/path`: redirects to the IdP with `state`, `nonce` and a PKCE S256 challenge, kept server-side in `cp_login_states`. `next` must be a same-origin relative path.
    - `GET /auth/callback`: exchanges the code over the guarded client, then validates the ID token (`iss`, `aud`, `exp`, `nonce`; algorithms RS256/ES256/EdDSA from JWKS). It maps roles through `role_map`, upserts `cp_users` and creates the session.
      - The cookie is `a2agw_session`: HttpOnly, `Secure` unless `cookie_secure=false`, `SameSite=Lax`, `Path=/`.
      - It redirects to `next`.
    - `POST /auth/logout` (CSRF) deletes the session.
    - `GET /api/v1/me` returns `{id, name, email, roles, permissions, csrf_token}`. The CSRF token is minted per session and stored as a digest.
  - API keys: `Authorization: Bearer <key>` maps to an `Actor` of kind `api_key` with the key's role. API keys are not subject to CSRF.

**Decisions:**
- **No local passwords.** People sign in through OIDC. Automation and break-glass access use API keys created from the CLI or by an admin.
- **Roles are re-derived from the ID token at each login.** An empty mapping means no permissions: the user sees 403 everywhere, plus a "no role assigned" message from `/me`. An admin can disable a user, which ends their sessions.
- **Sessions:** the session id is `secrets.token_urlsafe(32)`, stored as its digest. A new id is created at login (prevents session fixation). Expiry is the earlier of the absolute and idle limits; `last_used_at` is updated at most once a minute.

- [ ] **Step 1: Write the failing tests.**
  - `test_authn.py`:
    - `test_login_redirect_has_state_nonce_pkce`;
    - `test_callback_rejects_bad_state_nonce_iss_aud_exp`, parametrized;
    - `test_callback_creates_session_cookie_flags`;
    - `test_open_redirect_next_rejected`;
    - `test_session_idle_and_absolute_expiry` (fake clock);
    - `test_new_session_id_on_login`;
    - `test_logout_requires_csrf`;
    - `test_api_key_auth_and_revocation`;
    - `test_disabled_user_sessions_end`;
    - `test_no_secret_in_logs` (caplog at DEBUG over the whole flow).
  - `test_rbac.py`:
    - `test_every_route_declares_permission` (walk `app.routes`; each is in `ROUTE_PERMISSIONS` or explicitly public);
    - `test_role_matrix`, parametrized over every route × role: allowed routes don't return 403, denied ones return 403 and are audited;
    - `test_union_of_roles`;
    - `test_csrf_needed_for_session_writes_not_api_keys`.
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the full suite and ruff. Commit with `feat(control): OIDC sign-in, sessions, API keys, roles`.

---

### Task 6: Gateway channel (control-plane side)

**Files:**
- Create: `src/a2agw/control/channel.py`, `src/a2agw/control/admin.py` (the gateway management routes; Task 10 adds the rest).
- Modify: `src/a2agw/control/app.py`.
- Test: `tests/control/test_channel.py`, `tests/control/test_gateways.py`.

**Interfaces:**
- Produces:
  - **Gateway authentication:** `Authorization: Bearer <gateway token>` resolves to a gateway id through `cp_gateway_tokens` (digest lookup, not revoked, gateway active). Anything else gets 401. These routes accept no other credentials.
  - **`GET /cp/v1/stream`** (SSE). The first frame is `event: hello`, `data: {gateway_id, server_time}`. After that:
    - `event: state`, `data: {version, hash, partners: [...], policy: dict|null}`, sent when `cp_desired.version` is greater than the version the gateway reported (query parameter `applied`);
    - `event: command`, `data: {id, kind, args, expires_at}`, for each pending, unexpired command (marked `delivered`);
    - a `: keepalive` comment every `stream_keepalive_s`.
    - The handler polls the store every 500 ms, so several control-plane replicas can serve streams.
    - The stream closes within one keepalive interval of the token being revoked.
  - **`POST /cp/v1/report`:**
    - Body: `{events: [GatewayEvent dicts], audit: [audit rows], health: {...}|null, metrics: {...}|null, results: [{id, status: "done"|"failed", result}], applied: {version, hash, status: "applied"|"rejected", reason?}|null, info: {version, agents: [...], base_url}|null}`.
    - Response: `{acked_audit_seq: int, accepted_events: int, dropped: int}`.
    - The body is limited to `report_max_bytes` (413 above it) and each list to `report_max_items`; the excess is dropped and counted in `dropped`.
    - Event kinds outside the four known ones are dropped.
    - Strings are cut to 256 characters, and `data` keys are allowlisted per kind.
    - Audit rows are stored as `cp_gateway_audit`, idempotent on `(gateway_id, seq)`.
    - A result for a command that isn't this gateway's, or isn't delivered, is ignored.
    - `applied` with status `rejected` is stored on the gateway (`info_json.last_rejection`) and audited as `cp.apply` with outcome `rejected`.
  - `compute_desired(store, gateway_id) -> DesiredState`:
    - `partners` is each partner assigned to the gateway in status `approved`, rendered as its approved version: `{id, card, card_hash, tier, credential_ref, tls_ref, tags, card_url}`;
    - `policy` is the assigned policy's pinned or latest version document.
    - The version increments only when the content hash changes.
  - Gateway management routes (`GATEWAYS_MANAGE`):
    - `POST /api/v1/gateways` with `{name}` returns `{id, name, token}` (the token is shown once);
    - `GET /api/v1/gateways` lists `{id, name, status, last_seen_at, connected: bool, version_applied, version_desired, last_rejection, info}`;
    - `POST /api/v1/gateways/{id}/tokens` rotates the token (the new token is shown once, the old one is revoked);
    - `POST /api/v1/gateways/{id}/revoke`.
  - `enqueue_command(store, gateway_id, kind, args, actor, ttl_s=60) -> str` and `wait_command(store, id, timeout_s) -> CommandRow`, for Task 11.

- [ ] **Step 1: Write the failing tests.**
  - `test_channel.py`:
    - `test_stream_requires_gateway_token`;
    - `test_hello_then_state_when_behind`;
    - `test_no_state_when_up_to_date`;
    - `test_commands_delivered_once_and_marked`;
    - `test_expired_command_never_delivered`;
    - `test_revoked_token_closes_stream_within_keepalive` (fake clock);
    - `test_token_cannot_read_other_gateway` (gateway A's token sees only A's commands and state);
    - `test_report_idempotent_audit_rows`;
    - `test_report_body_cap_413`;
    - `test_report_item_cap_counts_dropped`;
    - `test_unknown_event_kind_dropped`;
    - `test_report_strings_truncated_and_keys_allowlisted`;
    - `test_result_for_foreign_command_ignored`;
    - `test_rejected_apply_recorded_and_audited`;
    - `test_desired_version_bumps_only_on_hash_change`.
  - `test_gateways.py`:
    - `test_create_shows_token_once`;
    - `test_rotate_revokes_old`;
    - `test_list_connected_flag`;
    - `test_permissions`.
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the full suite and ruff. Commit with `feat(control): gateway channel, desired state and commands`.

---

### Task 7: Gateway connector

**Files:**
- Create: `src/a2agw/ops/cp_client.py`.
- Modify:
  - `src/a2agw/config.py`: the `control_plane:` section.
  - `src/a2agw/serve/host.py`: start and stop the connector in startup/shutdown; managed mode.
  - `src/a2agw/consult/registry.py`: `apply_remote(records)`.
  - `README.md`, `docs/control-plane.md` (the gateway section).
- Test: `tests/ops/test_cp_client.py`, `tests/integration/test_cp_gateway.py`.

**Interfaces:**
- Consumes: Task 6's wire format and Task 1's `actions` and `set_policy`.
- Produces:
  - Config:

    ```yaml
    control_plane:
      url: https://cp.example.com
      token_env: A2AGW_CP_TOKEN
      tls_ref: null
      manage: [partners, policy]
      report_interval_s: 1.0
      health_interval_s: 15
    ```

    - `token_env` is required. `tls_ref` refers to the existing `tls:` map for mTLS.
    - `manage` takes a subset of `partners` and `policy`.
    - A `policy_file` together with `manage: [policy]` is a `ConfigError`.
    - Config-listed `partners:` together with `manage: [partners]` is a `ConfigError`.
  - `ControlPlaneConnector(host, cfg, *, http: httpx.AsyncClient | None = None, clock=time.monotonic, sleep=asyncio.sleep)` with `start()`, `stop()` and a `status() -> {connected, applied_version, last_error_kind, queue: int, dropped: int}` that is exposed at `/a2agw/admin/healthz`.
  - `PartnerRegistry.apply_remote(records: list[dict]) -> ReloadPlan`. It reuses the `prepare_reload`/`apply_reload` semantics, with each record validated as a `PartnerRecord` and its card hash checked against the card. A partner removed while it has open partner tasks is **disabled** at once and removed by maintenance when its handles drain.
  - Table `a2agw_cp_state(key PK, value_json)` on the gateway: `applied_state` (the last applied desired-state document) and `audit_acked_seq`.

**Decisions:**
- **Stream loop:**
  - Connect to `GET {url}/cp/v1/stream?applied=<version>` through the guarded client at tier `internal`.
  - On `state`, apply it under a lock. Apply partners first, then the policy.
    - A partner record is applied only if the local checks pass: SSRF on the card endpoints, signature verification for tiers in `require_signed`, and `card_hash` equal to the hash of `card`.
    - The policy is validated with `Policy.model_validate`.
    - If anything fails, nothing from that state is applied. Report `applied: {status: "rejected", reason}` (the reason is a class name or the dotted fields), and audit `cp.reject`.
    - On success, save `applied_state`, audit `cp.apply` with `detail.version` and `detail.hash`, and report `applied`.
  - On `command`, run the matching `actions` function as actor `cp:<command actor>`, then report its result. A command whose `expires_at` has passed is reported as `failed` with `{"error":"expired"}` and is not run. Command kinds:
    - `task.cancel`, `task.answer`, `task.get`;
    - `partner.refresh`, `partner.approve` (args `{id, expected_hash}`), `partner.reject`;
    - `tasks.reap`.
- **Reports:**
  - The connector subscribes to `host.bus` (`subscribe_with_replay(0)`) into a bounded queue (10 000; full drops the oldest and counts).
  - Every `report_interval_s` it posts up to 500 events, plus audit rows after `audit_acked_seq` (up to 500, ascending), plus health and metrics every `health_interval_s` (Task 3 snapshot), plus pending results.
  - `audit_acked_seq` advances only from the response, so unacknowledged audit rows are resent; the control plane is idempotent on them.
- **Back-off:** a disconnect or error retries with jittered exponential back-off (0.5 s up to 30 s). Connect and disconnect are audited as `cp.connect` (coalesced). A 401 stops the connector and logs one error naming `token_env` (never the token); `status()` shows `last_error_kind="unauthorized"`.
- **Fail static:**
  - When managed sections are configured, startup loads `applied_state` from `a2agw_cp_state` before serving. A gateway restarted while the control plane is down therefore serves its last-applied partners and policy.
  - With no cached state and an unreachable control plane, managed partners are empty and the policy is a lockdown: a lone deny with id `cp:unconfigured`, audited.
  - A warning in the log and in healthz says the gateway is waiting for its first state.

- [ ] **Step 1: Write the failing tests.**
  - `test_cp_client.py`, against a fake control plane (a Starlette app on `ASGITransport`, with scripted frames):
    - `test_applies_state_and_reports_applied`;
    - `test_ignores_older_or_equal_version`;
    - `test_rejects_state_with_bad_card_hash_keeps_previous`;
    - `test_rejects_state_with_unsafe_endpoint_keeps_previous`;
    - `test_rejects_invalid_policy_keeps_previous`;
    - `test_runs_command_and_reports_result`;
    - `test_expired_command_not_run`;
    - `test_backoff_capped_and_jittered` (fake sleep);
    - `test_401_stops_and_names_env_not_token`;
    - `test_audit_resent_until_acked_no_duplicates`;
    - `test_event_queue_bounded_counts_dropped`;
    - `test_config_conflicts_managed_and_local`.
  - `test_cp_gateway.py`, using a real control plane (Tasks 4-6) and a real gateway in-process:
    - `test_gateway_enrolls_receives_partners_and_policy`;
    - `test_cp_down_gateway_keeps_serving_then_resyncs`;
    - `test_gateway_restart_with_cp_down_uses_cached_state`;
    - `test_first_start_without_cp_is_lockdown`;
    - `test_removed_partner_with_open_tasks_disabled_then_removed`.
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3:** Implement. Write the gateway section of `docs/control-plane.md`.
- [ ] **Step 4:** Run the full suite and ruff. Commit with `feat(ops): control-plane connector with fail-static state`.

---

### Task 8: Partner catalogue (central registry)

**Files:**
- Create: `src/a2agw/control/catalogue.py`.
- Test: `tests/control/test_catalogue.py`.

**Interfaces:**
- Consumes:
  - `card_diff` (Task 1);
  - `guarded_async_client`;
  - the gateway's card parsing and validation (the same code path `PartnerRegistry.add_from_url` uses to fetch and normalize a card, factored into `consult/cardfetch.py` if needed);
  - `CardVerifier` built from `ControlSettings.trust`.
- Produces (routes):
  - **`POST /api/v1/partners`** (`PARTNERS_REGISTER`), body `{id, card_url | card, tier, credential_ref?, tls_ref?, tags?}`.
    - Fetches (SSRF-guarded by tier), validates and verifies the card, then stores version 1 with status `pending`.
    - Returns the partner detail. 409 on a duplicate id; 422 `{"error":"card","detail":<CardFetchError class>}`.
  - **`GET /api/v1/partners`** (`READ`): a list with `{id, tier, status, current_version, card_hash, name, skills_count, gateways: [ids], quarantined_on: [gateway ids]}`.
    - Filters: `tier`, `status`, `gateway_id`.
    - `q` is the skill search (spec §7.8): a case-insensitive keyword match over the approved card's name, description, skill names, skill descriptions and tags. Results are ranked by the number of matched terms, with skill-name matches weighted double, and each item gets `matched_skills: [skill ids]`.
  - **`GET /api/v1/partners/{id}`** (`READ`): the record, the current approved card, the latest pending version, `diff` (latest against approved), the version list and the per-gateway status from reports.
  - **`POST /api/v1/partners/{id}/approve`** (`PARTNERS_TRUST`), body `{version, expected_hash}`. Marks that version approved and the partner approved. Desired state is recomputed for assigned gateways.
    - If a gateway reported this partner quarantined with a pending hash equal to `expected_hash`, a `partner.approve` command is also queued for it.
  - **`POST /api/v1/partners/{id}/reject`** (`PARTNERS_TRUST`): sets status `rejected`, so the partner leaves desired state everywhere.
  - **`POST /api/v1/partners/{id}/quarantine`** (`PARTNERS_TRUST`): sets status `quarantined`, so the partner leaves desired state everywhere until it is approved again.
  - **`POST /api/v1/partners/{id}/refresh`** (`PARTNERS_REGISTER`): re-fetches the card. A significant change creates a new pending version (status stays `approved` with `pending: true`); a cosmetic change is applied as a new approved version.
  - **`PUT /api/v1/partners/{id}/settings`** (`PARTNERS_TRUST`): updates tier, credential_ref, tls_ref and tags. A tier change counts as a trust change and is audited.
  - **`PUT /api/v1/gateways/{gid}/partners`** (`ASSIGN`), body `{partner_ids: [...]}`: replaces the gateway's partner assignments.
- **Ingest hook:** `partner.state` events with `status="quarantined"` from a gateway are recorded per gateway. The partner list and detail show where a partner is quarantined. The control plane fetches the card itself for the diff and does not trust a card sent by the gateway.

**Decisions:**
- **Approval is pinned to a hash,** as on the gateway. An approve whose `expected_hash` doesn't match that version is 409.
- **Credentials stay references.** `credential_ref` and `tls_ref` are names that each gateway resolves from its own config. The control plane never holds partner secrets (spec §7.10, Credentials: "references only").

- [ ] **Step 1: Write the failing tests.**
  - `test_register_fetches_via_guarded_client_and_rejects_private_for_public_tier`;
  - `test_skill_search_ranks_skill_name_matches_first`;
  - `test_register_signed_required_tier_unsigned_422`;
  - `test_approve_requires_matching_hash`;
  - `test_approve_recomputes_desired_for_assigned_gateways`;
  - `test_reject_and_quarantine_remove_from_desired`;
  - `test_refresh_significant_change_creates_pending_with_diff`;
  - `test_refresh_cosmetic_auto_applies`;
  - `test_gateway_quarantine_report_shown_and_approve_queues_command`;
  - `test_detail_never_contains_secrets`;
  - `test_permissions`;
  - `test_every_write_audited`.
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the full suite and ruff. Commit with `feat(control): partner catalogue with approval, diff and assignment`.

---

### Task 9: Policies and dry-run

**Files:**
- Create: `src/a2agw/control/policies.py`.
- Test: `tests/control/test_policies.py`.

**Interfaces:**
- Consumes: `Policy`, `PolicyEngine` and `load_policy`'s validation messages (`security/policy.py`); `cp_gateway_audit` rows (Task 6).
- Produces (routes):
  - **`POST /api/v1/policies`** (`POLICY_EDIT`), body `{name, doc, comment?}`: creates a policy at version 1. A `doc` that fails validation is 422 with dotted `fields`.
  - **`POST /api/v1/policies/{id}/versions`** (`POLICY_EDIT`), body `{doc, comment?}`: adds a new version. The response includes `warnings`, e.g. `"lone deny rule locks down every agent"` and routing rules that name unknown partners.
  - **`GET /api/v1/policies`** and **`GET /api/v1/policies/{id}`** (`READ`): versions, plus a unified diff between consecutive versions (text over canonical YAML).
  - **`PUT /api/v1/gateways/{gid}/policy`** (`ASSIGN`), body `{policy_id, version | null}`: `null` means follow the latest version.
  - **`POST /api/v1/policies/dry-run`** (`POLICY_EDIT`), body `{doc, gateway_ids?: [...], days: 1..30 = 7}`, response:

    ```
    {"evaluated": int, "newly_blocked": [{gateway_id, seq, ts, actor_kind, agent_id, partner_id, action, rule}], "newly_allowed": [...], "truncated": bool, "not_replayable": ["egress content checks"]}
    ```

    - It replays `inbound.admit`/`authz.deny` rows through `authorize(principal, agent_id, None)`, and `partner.call`/`egress.deny` rows through the routing `forbid` check and the tier/partner classification ceilings using the row's `classification`.
    - It compares against what happened, evaluating at most 50 000 rows (newest first) with `truncated` set beyond that.
    - Principal ids appear only as `actor_kind`, never in full.

- [ ] **Step 1: Write the failing tests.**
  - `test_create_and_version_policy`;
  - `test_invalid_doc_422_fields_only`;
  - `test_lone_deny_warning`;
  - `test_assign_pinned_and_latest`;
  - `test_assignment_updates_desired_state`;
  - `test_dry_run_finds_newly_blocked_admit`;
  - `test_dry_run_finds_newly_forbidden_partner_call`;
  - `test_dry_run_classification_ceiling`;
  - `test_dry_run_truncates_at_cap`;
  - `test_dry_run_reports_not_replayable`;
  - `test_dry_run_no_principal_ids`;
  - `test_permissions`.
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the full suite and ruff. Commit with `feat(control): versioned policies, assignment and dry-run`.

---

### Task 10: Read APIs for the Console

**Files:**
- Create: `src/a2agw/control/views.py`, plus `src/a2agw/control/admin.py` (users, API keys, settings).
- Test: `tests/control/test_views.py`, `tests/control/test_admin_routes.py`.

**Interfaces:**
- Produces (every list is `{items: [...], next_cursor: str|null}`, with `limit` 1..200, default 50):
  - **`GET /api/v1/overview`** (`READ`):

    ```
    {"gateways": {"total", "connected", "stale"},
     "tasks_per_min": [{ts, count}],
     "error_rate": float,
     "top_partners": [{partner_id, calls, errors, p95_ms}],
     "alerts": [{kind, gateway_id?, partner_id?, since}]}
    ```

    - `tasks_per_min` covers the last 60 one-minute buckets, from `task.state` events.
    - `error_rate` is computed over the last 15 minutes.
    - Alerts: a gateway disconnected for more than 60 s; a partner whose breaker is open; a partner quarantined on any gateway; a rejected desired state; an audit chain break reported by a gateway.
  - **`GET /api/v1/agents`** (`READ`): hosted agents from each gateway's `info.agents` (id, name, version, skills, card_url, gateway_id, health), together with the catalogue partners (tier, status, health from metrics). Filter `kind=hosted|partner`.
  - **`GET /api/v1/tasks`** (`READ`):
    - filters: `gateway_id`, `agent_id`, `state`, `since`, `trace_id`, `q` (a task-id prefix);
    - built from the latest `task.state` event per `(gateway_id, task_id)`;
    - items: `{gateway_id, agent_id, task_id, context_id, state, updated_at, trace_id}`.
  - **`GET /api/v1/tasks/{gateway_id}/{agent_id}/{task_id}`** (`READ`):
    - queues a `task.get` command and waits up to 5 s, returning the gateway's task detail (Task 2) plus `timeline`;
    - `timeline` holds every stored event sharing the task's `trace_id`, across all gateways, ordered by `ts`: task state changes and partner calls with durations;
    - if the gateway doesn't answer in time: 202 `{command_id, timeline}`.
  - **`GET /api/v1/topology`** (`READ`), query `window_m` 5..1440 = 60:
    - returns `{nodes: [{id, kind: "hosted"|"partner", gateway_id?}], edges: [{from, to, calls, errors, p50_ms, p95_ms, policy: "allowed"|"forbidden"|"forced"|"preferred"}]}`;
    - built from `partner.call` events;
    - the `policy` overlay comes from evaluating each gateway's current policy `route()` for the edge.
  - **`GET /api/v1/audit`** (`AUDIT_READ`):
    - filters: `source=control|gateway`, `gateway_id`, `action`, `actor`, `agent`, `partner`, `since`, `until`;
    - `GET /api/v1/audit/export?format=jsonl|csv&...` (`AUDIT_READ`) streams up to 100 000 rows, with the CSV formula-injection guard (cells starting with `= + - @` are prefixed with `'`). The export is itself audited.
    - `GET /api/v1/audit/verify` (`AUDIT_READ`) verifies the control plane's own chain.
  - **`GET /api/v1/credentials`** (`READ`): the credential and TLS ref names each gateway reported in `info` and that catalogue partners use. Names only; no values are ever held.
  - **Users, API keys and settings:**
    - `GET /api/v1/users` and `PATCH /api/v1/users/{id}` with `{disabled?}` (`USERS_MANAGE`);
    - `GET/POST /api/v1/api-keys` and `POST /api/v1/api-keys/{id}/revoke` (`APIKEYS_MANAGE`). A key is shown once at creation; an admin can't create a key with a role they don't hold.
    - `GET /api/v1/settings` (`SETTINGS_MANAGE`): the effective settings without secrets. Settings are read-only from the API in 4a; edits go through the config file.

- [ ] **Step 1: Write the failing tests.**
  - `test_views.py`:
    - `test_overview_buckets_and_alerts` (fake clock, seeded events);
    - `test_agents_merge_hosted_and_partners`;
    - `test_tasks_latest_state_per_task_and_filters`;
    - `test_task_detail_via_command_and_timeline_across_gateways`;
    - `test_task_detail_202_when_gateway_slow`;
    - `test_topology_edges_latency_and_policy_overlay`;
    - `test_audit_filters_both_sources`;
    - `test_export_csv_formula_guard_and_audited`;
    - `test_credentials_names_only`;
    - `test_pagination_cursor_stable`.
  - `test_admin_routes.py`:
    - `test_disable_user_ends_sessions`;
    - `test_api_key_shown_once_and_role_ceiling`;
    - `test_settings_redacted`;
    - `test_permissions`.
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3:** Implement. Aggregations are computed on query over `cp_events` with indexed time ranges. No materialized tables are needed at 4a scale; the 7-day retention bounds them.
- [ ] **Step 4:** Run the full suite and ruff. Commit with `feat(control): read APIs for overview, agents, tasks, topology, audit`.

---

### Task 11: Operator actions

**Files:**
- Create: `src/a2agw/control/operations.py`.
- Test: `tests/control/test_operations.py`.

**Interfaces:**
- Consumes: `enqueue_command` and `wait_command` (Task 6).
- Produces (routes, all `TASKS_OPERATE`, all audited as `cp.command` with `detail.command=kind`):
  - `POST /api/v1/tasks/{gateway_id}/{agent_id}/{task_id}/cancel`;
  - `POST /api/v1/tasks/{gateway_id}/{agent_id}/{task_id}/answer`, body `{text}` (≤ 32 KiB);
  - `POST /api/v1/gateways/{gateway_id}/reap`, body `{agent_id, confirm: bool, force: bool}`;
  - `POST /api/v1/partners/{id}/gateways/{gateway_id}/refresh`.
  - Each queues the command and waits up to 10 s:
    - when it's done: 200 `{command_id, status, result}`;
    - when the gateway reports a failure: 409 `{command_id, status: "failed", result}`;
    - when it's still pending: 202 `{command_id, status: "pending"|"delivered"}`.
  - `GET /api/v1/commands/{id}` (`READ`): `{id, gateway_id, kind, status, result, actor, created_at, finished_at}`.
  - Commands expire 60 s after creation. Expiry is final: the stream never delivers an expired command.

- [ ] **Step 1: Write the failing tests.**
  - `test_cancel_round_trip_through_connector` (a real gateway);
  - `test_answer_round_trip_resumes_task`;
  - `test_offline_gateway_202_then_expired`;
  - `test_expired_never_delivered_after_reconnect`;
  - `test_failed_command_409_with_reason`;
  - `test_answer_size_cap`;
  - `test_permissions_viewer_403`;
  - `test_audited_with_actor`.
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the full suite and ruff. Commit with `feat(control): operator actions as gateway commands`.

---

### Task 12: "Done when" end-to-end test, docs and hardening review

**Files:**
- Create:
  - `tests/integration/test_phase4a_control_plane.py`;
  - `docs/control-plane.md` (complete);
  - `examples/control_plane/` (a `control.yaml`, two gateway configs and a README walkthrough).
- Modify:
  - `README.md`: a Control plane section, the Roadmap, Known limitations, and the Configuration section (the `control_plane:` key).
  - `docs/boundary-conditions.md`: control-plane rows.
  - `examples/docker/compose.yaml`: an optional `control-plane` service behind a profile.
- Test: the new integration file, plus `tests/test_examples_docker.py` for the profile.

**Interfaces:**
- Consumes: everything above.
- Produces: `test_phase4a_control_plane.py::test_console_operations_across_two_gateways`. One test, with readable phases, against a control plane and two in-process gateways (`gw-east` and `gw-west`) with fake-model agents and a fake partner:
  1. An admin creates the gateways, plus API keys for each role. Each gateway connects with its token.
  2. A security user registers partner `p` and sees it pending. A viewer cannot approve it (403). Security approves it with the hash.
  3. An admin assigns `p` and a policy to both gateways. Both apply them (the `applied` version shows in the gateway list).
  4. A dry-run of a stricter policy lists the calls it would block. Saving and assigning it changes behaviour on both gateways.
  5. Agents on `gw-east` call `p`. Overview, tasks, the topology edges and a task's cross-gateway timeline all reflect it.
  6. The partner's card changes. `gw-west` quarantines it on refresh; the control plane shows the quarantine and the diff. Security approves it, and the command clears the quarantine on `gw-west`.
  7. An operator cancels a running task on `gw-east` (its partner task is cancelled too), then answers an `input-required` task on `gw-west`, which completes.
  8. The control plane is stopped. Both gateways keep serving with their applied state. The control plane is restarted, and they reconnect and resend unacknowledged audit rows.
  9. A security user exports the audit log (CSV and JSONL): control-plane rows and both gateways' rows are present, and both chains verify.
  10. An admin revokes `gw-west`'s token. Its stream ends and it reports `unauthorized`, while `gw-east` is unaffected.

- [ ] **Step 1: Write the end-to-end test.** Run it; it fails until any gaps it finds are fixed in the owning modules.
- [ ] **Step 2: Security pass.** Add tests where any is missing:
  - `test_no_secret_reaches_any_response_log_or_audit`: scan every response body, caplog and audit row in the end-to-end run for the gateway tokens, API keys, session id and client secret;
  - `test_gateway_cannot_post_events_as_other_gateway`;
  - `test_cp_card_fetch_ssrf_matrix` (reusing the Phase 2 SSRF payload list).
- [ ] **Step 3: Docs.**
  - `docs/control-plane.md`: deployment, enrollment, roles and permissions table, API overview (link the OpenAPI document), managed versus local mode, fail-static behaviour, command semantics, retention, multi-replica notes (streams poll the store; consult tokens stay per gateway process).
  - README: the new sections.
  - The boundary-conditions rows for review focus items 1-5.
- [ ] **Step 4:** Run the full suite (including Postgres), the TCK, ruff and `scripts/test-crewai.sh`. Commit with `test(control): phase 4a end-to-end; docs`.

---

## Known limitations accepted for 4a

These go in `docs/control-plane.md` and the README:

- **Single tenant.** One control plane serves one organization. The spec's tenants (Settings screen) are deferred, and the tables have no tenant column yet.
- **Limits and budgets aren't policy yet.** The spec's Policies screen covers "limits, budgets", but the gateway keeps limits in its config file (`limits:`), not in the policy document, and token or cost budgets aren't enforced yet (§11a.3). The control plane shows each gateway's effective limits read-only (from `info`); distributing them is deferred.
- **Settings are file-managed.** `GET /api/v1/settings` is read-only.
- **Traces are only as good as the events.** The timeline comes from forwarded events, not OTel spans; a full span view needs an OTLP backend.
- **Egress content checks can't be replayed** in the dry-run: the message text is never stored.
- **Answering `auth-required` prompts from the Console is refused** by design.
