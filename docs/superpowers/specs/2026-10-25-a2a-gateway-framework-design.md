# A2A Gateway Framework — Design

- **Date:** 2026-10-25
- **Status:** Approved 2026-10-25. The user asked to go with all recommended approaches and to add a corporate control panel plus agent clusters (§7.10–7.11).
- **Working name:** `a2a-gateway` (Python import `a2agw`). This name is a placeholder and Claude's call.

## 1. Intent

Agents built with any framework (LangChain, LangGraph, CrewAI, OpenAI Agents SDK, Claude Agent SDK, Google ADK, AutoGen/AG2, LlamaIndex, or plain code) should be able to work together over the A2A protocol without custom wiring for each pair.

The framework provides two directions:

- **Inbound:** it makes any agent a standards-compliant A2A server.
- **Outbound:** it gives any agent a registry of *partner agents*, registered by their Agent Cards. Partners are exposed to the agent as tools.

The agent's own reasoning can then decide which partner to consult for which kind of task, the way a company routes work between specialist teams. The aim is to let many role-specific agents cooperate on large, multi-step projects across dynamic systems, reliably enough for production.

Partners may be **outside the operator's control**: other teams, other companies, or publicly listed global agents. Every remote party is therefore untrusted by default.

## 2. Goals

1. **Plug-and-play for any framework.** There are two ways to plug in:
   - *Embedded:* a small adapter inside the agent process.
   - *Sidecar gateway:* a separate process that agents in any language reach over HTTP or MCP.
2. **Full A2A 1.0 compliance, inbound and outbound.** This covers:
   - Messages, tasks, streaming, push notifications, cancellation, resubscription, and multi-turn (`input-required` / `auth-required`).
   - Agent Card serving, the extended card, and signed cards.
   - Backward compatibility with 0.3, through the SDK's compatibility mode.
3. **A partner registry.** It holds:
   - Partners added from a card URL, a file, or a central registry.
   - Card validation, signature verification, refresh, and change detection.
   - Per-partner credentials and policy.
4. **Partners as tools.** Each partner or skill is projected into the tool format the host framework expects. Long-running and multi-turn partner tasks are modeled correctly, not squeezed into a single request/response.
5. **Intelligent delegation.** By default, the agent's LLM chooses partners from rich tool descriptions. Operators can add deterministic routing rules. A discovery tool keeps tool lists small when there are many partners.
6. **Security fit for untrusted, global partners.** This covers authentication, authorization, egress control, SSRF protection, prompt-injection containment, limits, and audit.
7. **Robustness.** This covers deadlines, retries, circuit breakers, durable tasks, cancellation cascades, loop and recursion prevention, and graceful degradation.
8. **Observability.** End-to-end distributed traces across agent hops, plus metrics and audit logs.

## 3. Non-goals

- **Re-implementing the A2A protocol.** We build on the official `a2a-sdk`.
- **Being an agent framework or LLM planner.** Host agents keep their own reasoning. We supply partners, context, and guardrails.
- **Hosting or running other people's agents.**
- **A graphical UI in Phases 1–3.** The Console arrives in Phase 4 (§7.10). Earlier phases expose the management API it will use.
- **Language SDKs other than Python in v1.** Non-Python agents use the sidecar.

## 4. Anti-goals

The framework fails, even if it technically works, if any of these happen:

- It locks users into one agent framework, or the core imports any agent framework.
- Remote content (cards, messages, artifacts) is trusted implicitly, or acted on as instructions.
- Agents can call each other in unbounded loops, or exceed cost or time budgets without stopping.
- Many partners turn into a tool list so large the LLM can't use it.
- A long-running partner task is reported as a failure because it didn't finish within one tool call.

## 5. Constraints and grounding

- **SDK:** `a2a-sdk` is at 1.2.3 (2026-10-19). It requires Python ≥ 3.10 and implements A2A spec 1.0 with 0.3 compatibility.
  - Its extras cover our needs: `http-server`, `fastapi`, `grpc`, `sql` / `sqlite` / `postgresql` / `mysql` task stores, `signing`, `encryption`, and `telemetry`.
- **Spec facts we design around (A2A 1.0):**
  - **Operations:** `SendMessage`, `SendStreamingMessage`, `GetTask`, `ListTasks`, `CancelTask`, `SubscribeToTask`, the push-notification-config CRUD operations, and `GetExtendedAgentCard`.
  - **Task states:**
    - *Terminal:* `completed`, `failed`, `canceled`, `rejected`.
    - *Interrupted:* `input-required`, `auth-required`.
  - **Bindings:** JSON-RPC, gRPC, and HTTP+JSON.
  - **Headers:** `A2A-Version` for version negotiation, `A2A-Extensions` for extensions.
  - **Multi-tenancy:** an optional `tenant` on each interface.
  - **Security schemes:** API key, HTTP auth, OAuth2, OIDC, and mTLS.
  - **Signed cards:** `AgentCardSignature`.
- **Local machine:** Python 3.9 is installed and `uv` is available. The project uses `uv` with a pinned Python 3.12 (Claude's call). Supported versions are 3.11 and up.
- **Repository:** the project folder is empty, and there is no git repository yet.

## 6. Approaches considered

| | Approach | Trade-off |
|---|---|---|
| **A (chosen)** | One framework-agnostic core, deployable **embedded** (library) or as a **sidecar/gateway** service, with an optional shared registry | Gets both easy plug-in and central governance. Costs two deployment modes to test. |
| B | Central gateway only (an "API gateway for agents") | Single enforcement point and strongest central control. Costs an extra hop per call, creates a single point of failure, and is heavier to operate. Agents still need adapters. |
| C | Extend an existing platform (for example ADK's built-in A2A) | Fastest demo, but ties the design to one framework. Contradicts the core goal, so rejected. |

The user chose **A**. B remains possible as a deployment of A: run the sidecar centrally and point every agent at it.

## 7. Architecture

```
            ┌──────────────────────── a2agw core (framework-agnostic) ────────────────────────┐
 inbound    │  Serve: card builder · A2A server (JSON-RPC/REST/gRPC via a2a-sdk) · authn/authz │
 A2A ──────▶│         task store · executor bridge · push sender · limits                      │
            │                                                                                  │
            │  Consult: partner registry · card fetch/verify/refresh · partner client          │
 outbound   │           (resilience, credentials, egress policy) · tool projection · router    │──────▶ partner
 A2A ◀──────│                                                                                  │        agents
            │  Cross-cutting: call-context (trace, hop budget, deadline) · policy engine ·     │
            │                 audit · OpenTelemetry · config                                   │
            └───────────────▲───────────────────────────────────────────▲──────────────────────┘
                            │ adapter SPI                                │ sidecar API
          ┌─────────────────┴───────────────┐            ┌───────────────┴───────────────┐
          │ adapters: callable · LangChain · │            │ gateway service: HTTP + MCP   │
          │ LangGraph · CrewAI · OpenAI ·    │            │ for agents in any language    │
          │ Claude SDK · ADK · AG2 · LlamaIdx│            └───────────────────────────────┘
          └──────────────────────────────────┘
```

### 7.1 Adapter SPI: the only framework-specific code

An adapter implements two small interfaces.

**`InboundAdapter`**
- **Input:** the incoming request context, which holds the message parts, `contextId`, the existing task, and the caller identity.
- **Output:** an async stream of framework-neutral events: `Status(working, text)`, `ArtifactChunk(parts, append, last)`, `NeedInput(question)`, `NeedAuth(scheme)`, `Done`, and `Failed(error)`.
- The core maps these events to A2A task updates.
- `contextId` maps to the framework's thread or session ID, so multi-turn conversations persist.

**`ToolProjector`**
- **Input:** framework-neutral `PartnerTool` specs.
- **Output:** the framework's native tool objects. Examples:
  - LangChain `StructuredTool`
  - OpenAI Agents `FunctionTool`
  - Claude Agent SDK MCP tool
  - ADK `FunctionTool` or `RemoteA2aAgent`
  - CrewAI `BaseTool`
- The projector wraps them so that each call goes through the core `PartnerClient`.

**`CallableAdapter`**
- The universal fallback: any `async def handle(ctx) -> AsyncIterator[Event] | str` becomes an A2A agent.
- On the outbound side it projects partners as plain async Python functions with JSON schemas.

### 7.2 Inbound (Serve)

**Agent Card**
- Built from code or config: name, description, provider, version, skills (id, description, tags, examples, input and output modes), capabilities, security schemes, and interfaces.
- Served at `/.well-known/agent-card.json`, with an optional extended card for authenticated callers.
- Can optionally be signed with an operator key, using the SDK `signing` extra.

**Transport**
- Mounted on Starlette/FastAPI using the SDK's request handlers.
- JSON-RPC and HTTP+JSON are on by default. gRPC is opt-in.

**Executor bridge**
- Implements the SDK `AgentExecutor`.
- Runs the adapter, maps its events to `TaskStatusUpdateEvent` and `TaskArtifactUpdateEvent`, and supports cooperative cancellation through an `asyncio` cancel scope.

**Task store**
- SQLite in development and PostgreSQL in production, through the SDK SQL stores.
- Tasks survive restarts. A task that was interrupted mid-run is marked `failed` with a reason: no silent loss.

**Push notifications**
- Webhook URLs are validated with SSRF rules (§7.5) and signed with a per-config token or JWT.
- Delivery is retried with backoff.

**Limits**
- Per-caller rate limits and concurrency caps.
- A maximum message size, maximum number of parts, and maximum file size.
- An allowlist of accepted MIME types.

### 7.3 Outbound (Consult)

**Partner registry**

Partners can come from three sources:
- A card URL: the framework fetches `/.well-known/agent-card.json`.
- A local YAML/JSON file.
- A central registry service (Phase 4).

Each partner record holds:
- The card and a hash of it.
- Trust tier: `internal`, `partner`, or `public`.
- A credential reference.
- Policy (§7.5).
- Tags and the time it was last verified.

Validation and refresh:
- **Validation:** the card is checked against the schema and size limits. Signature verification is required for the `partner` and `public` tiers when configured.
- **Refresh:** a TTL combined with ETag/`Cache-Control`.
- **Change detection:** if skills, endpoints, or security schemes change, the partner is quarantined until approved, or auto-accepted according to policy. This prevents silent swaps of a card.

**PartnerClient**
- Built on the SDK client factory.
- **Connection:** selects a binding (prefers JSON-RPC, then REST, then gRPC), pins `A2A-Version`, and negotiates extensions.
- **Credentials:** obtained from a `CredentialProvider` interface. Implementations cover environment variables, file, OAuth2 client credentials with a token cache, and mTLS, and the interface can be extended for vaults.
- **Resilience:**
  - A per-call deadline.
  - Retries with jittered backoff, only where safe: connection errors before the request is accepted, and idempotent reads.
  - `SendMessage` is never retried blindly. The client reuses the same `messageId` and checks for an existing task before re-sending.
  - A circuit breaker and a concurrency bulkhead per partner.
- **Streaming:** prefers streaming when the partner supports it. If the stream drops, the client falls back to `SubscribeToTask`, then to polling `GetTask`.

**Tool projection**

Each partner becomes one tool by default. Per-skill tools are opt-in, for partners with very different skills. Tool descriptions are generated from the card: the description, the skills with their examples and tags, input/output modes, and the trust tier.

Every partner tool has a common call shape: `message`, optional `files`/`data`, optional `task_id` and `context_id` to continue a conversation, and optional `wait_seconds`.

The tool result is always a structured envelope:

```
{ partner, task_id, context_id, state, text, artifacts[...], question?, provenance }
```

The `state` field drives what happens next:
- **`completed`:** the result is returned.
- **`input-required` / `auth-required`:** the partner's question is returned. The agent answers by calling the same tool with `task_id`.
- **`working` after `wait_seconds`:** a handle is returned. The agent can call the companion tools `a2a_check_task(task_id)`, `a2a_cancel_task(task_id)`, or `a2a_wait(task_ids[], seconds)` to fan in several parallel partner tasks.

**Discovery mode**
- Applies when the number of partners exceeds a threshold (default 12).
- Instead of N tools, the agent gets `find_partners(need)`, which ranks cards by keyword or embedding match, plus a generic `consult_partner(partner_id, ...)`.
- This avoids tool explosion.

**Routing rules (optional)**
- Declarative rules match on skill tags, task type, or data classification.
- Examples: "security reviews → `secaudit` agent"; "PII never goes to `public` tier".
- Rules can **force**, **prefer**, or **forbid** partners.
- Forced routes are applied by the projector, and forbidden partners are hidden from that agent.

### 7.4 Call context: making a network of agents safe

Every outbound call carries a call context, sent as an A2A extension. The extension URI is `https://a2agw.dev/ext/call-context/v1`, a placeholder URI and Claude's call. It is sent in message `metadata` and declared in cards. It contains:

- `trace` (W3C `traceparent`).
- `origin` (the root agent and request ID).
- `hop` and `max_hops` (default 8).
- `path`, a list of agent IDs used to detect cycles.
- `deadline`, an absolute timestamp.
- `budget`, optional limits on cost, tokens, or calls.

Inbound gateways enforce these limits:
- A call is rejected if the hop limit is exceeded or a cycle appears in `path`. A cycle is allowed only when policy explicitly permits re-entry.
- Deadlines and budgets shrink at each hop.
- Partners that don't support the extension just ignore it. The local gateway still enforces the limits on its own side.

Cancellation also cascades. If a task is canceled inbound, every partner task it started is canceled too.

### 7.5 Security and trust

**Inbound authentication**
- API key, OAuth2/OIDC JWT validation (JWKS with caching), and mTLS.
- The schemes are declared in the card.
- Invalid credentials get 401 and unauthorized requests get 403. The server doesn't reveal whether a task exists to unauthorized callers.

**Authorization**
- A policy engine maps caller → allowed skills, tenants, and rate limits.
- Tasks are owned by the caller who created them. Only that caller (or an admin) can get, cancel, or subscribe to a task.

**Egress control (outbound)**
- Each partner tier has a data policy.
- Optional classifier and redaction hooks run on outgoing parts.
- Allowlists for hosts and schemes, and https only outside development.

**SSRF protection**
- Applies to card URLs, partner endpoints, push webhooks, and file-part URLs.
- Hostnames are resolved and checked. Private, loopback, link-local, and metadata IP ranges are blocked unless the partner is in the `internal` tier.
- Redirects are capped and re-checked.

**Prompt-injection containment**
- Partner output is returned in a provenance-tagged envelope marked untrusted.
- Projectors add a standard system note to the host agent: content from partners is data, not instructions.
- Size caps and MIME checks apply. Remote files are never executed or auto-fetched; downloads are opt-in with size limits.

**Cards**
- Signature verification is optional per tier.
- Endpoints are pinned. Card changes are quarantined (§7.3).

**Secrets**
- Secrets are never written to logs or traces, and they're redacted in audit records.

**Audit log**
- An append-only record of who called what, when, which partner, the data classification, and the outcome.

### 7.6 Observability

- **Tracing:** OpenTelemetry spans for inbound tasks, adapter runs, and outbound partner calls. Trace context is propagated across hops (§7.4), so one trace covers the whole agent network.
- **Metrics:** latency, error rate per partner, circuit-breaker state, task counts by state, and hop depth.
- **Logs:** structured JSON logs with trace IDs.

### 7.7 Sidecar / gateway mode (Phase 3)

The same core runs as a service configured by `a2agw.yaml`.

**Inbound for non-Python agents**
- The gateway serves A2A on the agent's behalf.
- It forwards work to the agent through a simple local contract: an HTTP webhook (`POST /a2agw/invoke`) with streaming response events, or stdio.

**Outbound for any agent**
- **As an MCP server:** each partner becomes an MCP tool, plus the task tools from §7.3. Any MCP-capable agent can plug in with zero code. This includes Claude Code, Claude Agent SDK, OpenAI Agents, Cursor, and LangChain MCP adapters.
- **As a REST API:** `POST /partners/{id}/messages` and related endpoints.

The sidecar can also be deployed centrally as a shared gateway. This is approach B, as a deployment choice.

### 7.8 Central registry (Phase 4, optional)

A service for a whole organization's agent network:
- A catalogue of cards with approval workflow and trust tiers.
- Health checks.
- Search over skills.
- Policy distribution to gateways.

Gateways subscribe to it as a registry source.

### 7.9 Developer experience

**CLI**
- `a2agw init` scaffolds an agent.
- `a2agw serve` runs it.
- `a2agw partners add <url>` and `partners list|verify|approve` manage partners.
- `a2agw card validate|sign` checks and signs cards.
- `a2agw call <partner> "msg"` sends a test message.
- `a2agw trace <id>` shows a trace.

**Config**
- Code-first API plus YAML. Environment variables can be interpolated for secrets.

**Examples**
- A "software company" network: an orchestrator/PM agent (LangGraph), architect (OpenAI Agents), coder (Claude Agent SDK), reviewer (CrewAI), and security auditor (plain callable).
- The PM delegates, fans out, and handles `input-required`. One trace covers the whole run.

### 7.10 Control plane and Console (Phase 4)

The user wants a corporate-grade control panel for operating and configuring A2A across many agents and clusters.

**Control plane service** (FastAPI + PostgreSQL)
- Builds on the central registry (§7.8).
- **Owns:** the agent and partner catalogue, trust tiers, approvals, policies and routing rules, clusters (§7.11), users and RBAC, and audit.
- **Gateways connect outbound:** each gateway connects to the control plane over an authenticated channel to receive config and policy and to push events, health, and metric summaries. Gateways never need to be reachable from the control plane.

**Management API on every gateway** (built from Phase 1, read-only at first)
- `GET /a2agw/admin/{agents,partners,tasks,events}`.
- An SSE event stream of task state changes and partner calls.
- The control plane and the CLI both use it.

**Console**
- A web app: React + TypeScript + Vite, shadcn/ui + Tailwind, TanStack Query, React Flow for graphs, and ECharts for metrics.
- Supports light and dark themes, SSO through OIDC, and RBAC with the roles Viewer, Operator, Admin, and Security.
- **Screens:**
  - **Overview:** network health, tasks per minute, error rates, top partners, and alerts.
  - **Agents:** inventory of hosted and partner agents, card viewer, skills, trust tier, health, and versions.
  - **Register partner:** paste a card URL. The console fetches and validates the card, verifies the signature, shows a diff on change, and handles approve, quarantine, or reject.
  - **Topology:** a live graph of who calls whom, with edge latency and errors and policy overlays (allowed, forbidden, forced).
  - **Clusters:** create and edit agent teams (§7.11), assign roles, set routing rules, and launch a project.
  - **Tasks and traces:** search tasks, open one to see the full cross-agent timeline, messages, artifacts, and `input-required` prompts. Operators can answer a prompt or cancel a task from here.
  - **Policies:** authz, egress, tiers, limits, budgets, and routing rules. Every policy has a dry-run "what would be blocked" view.
  - **Credentials:** references only. Secrets stay in the vault or environment and are never displayed.
  - **Audit:** a filterable log with export.
  - **Settings:** gateways, tenants, users, and API keys.

### 7.11 Clusters (agent teams) and projects (Phase 5)

A **cluster** is a named team of agents (hosted or partner) with roles. Examples: PM/orchestrator, architect, coder, reviewer, QA, security.

A cluster definition includes:
- An **orchestrator** (any agent that uses the gateway). The framework ships a reference orchestrator agent built on LangGraph with Claude by default; any model can be configured.
- **Routing rules** scoped to the cluster.
- **Budgets and deadlines.**
- **Human-in-the-loop checkpoints.**

**Running a project**
1. The user submits a project goal to a cluster from the Console or the API.
2. The orchestrator breaks it into work items and delegates them to members through A2A.
3. The orchestrator tracks the items on a project board: pending, delegated, `input-required`, done, and failed.
4. It escalates questions it can't resolve to a human in the Console.
5. It assembles the final artifacts.

Each project gets one root trace, so the whole collaboration can be replayed in Tasks and traces.

Clusters are config: YAML in git or the Console, versioned. They can nest, because a cluster can expose itself as one A2A agent with its own card. Nesting is how large organizations compose teams of teams.

## 8. Boundary conditions to handle explicitly

1. **Partner down or slow.** Covered by the circuit breaker, the deadline, and a tool result of `state=unavailable` with retry-after. The host agent can choose an alternative.
2. **Partner never finishes.** The deadline gives the agent a handle, and a TTL cancels the task.
3. **Stream drops mid-task.** The client resubscribes, then falls back to polling. Artifacts are de-duplicated by id and `append`/`lastChunk`.
4. **Gateway restarts mid-task.**
   - Inbound tasks are restored from the store, and interrupted tasks are failed with a reason.
   - Outbound task handles are persisted, so they can be resumed.
5. **Duplicate deliveries.** Handled with an idempotent `messageId` and dedupe of push events.
6. **Version mismatch.** Version negotiation happens explicitly, and a clear error is returned. There is no silent fallback.
7. **Card changed or spoofed.** The partner is quarantined, and the signature and pin are checked.
8. **Huge or malicious payloads.** Size, part, and MIME limits apply. Unknown parts are rejected.
9. **Cycles and runaway recursion.** Hop, path, deadline, and budget limits (§7.4) stop them.
10. **Many partners.** Discovery mode (§7.3) takes over.
11. **Auth expiry mid-task.** Tokens are refreshed. A partner's `auth-required` is surfaced to the agent or operator.
12. **Multi-tenant partners.** The `tenant` is routed per interface.
13. **0.3-only partners.** They are handled by the SDK compatibility mode, and flagged in the registry.

## 9. Phasing

Each phase gets its own implementation plan. Phase 1 must be useful on its own.

| Phase | Scope | Done when |
|---|---|---|
| **1. Core** | Package skeleton; Adapter SPI; Callable, LangChain, and LangGraph adapters; inbound Serve (card, JSON-RPC + REST, SQLite store, streaming, cancel, multi-turn); outbound Consult (file/URL registry, PartnerClient with deadline, retry, and breaker; tool projection with task handles); call-context extension; API-key + JWT auth; OTel tracing; read-only management API + SSE event stream; multi-agent `AgentHost`; CLI basics | A three-agent demo across two frameworks works end to end, including `input-required` and a long task, and passes the A2A conformance suite (`a2a-tck`) for inbound |
| **2. Hardening** | Signed cards and quarantine; OAuth2 client credentials + mTLS; policy engine (authz, egress, routing rules); SSRF guard; injection envelope; push notifications; Postgres store; discovery mode; audit log; fault-injection tests | The security and chaos test suites pass, and boundary conditions 1–13 are covered by tests |
| **3. Gateway** | Sidecar service; MCP server outbound; HTTP webhook inbound contract; adapters for CrewAI, OpenAI Agents, Claude Agent SDK, ADK, AG2, and LlamaIndex; Docker image | A non-Python agent and an MCP-only agent join the demo network |
| **4. Control plane + Console** | Central registry and control-plane service; gateway↔control-plane channel; Console (all §7.10 screens), SSO/RBAC; Helm chart; ops docs | Operators register, approve, and monitor partners, edit policy, and inspect cross-agent traces entirely from the Console, across multiple gateways |
| **5. Clusters & projects** | Cluster model; reference orchestrator agent; project board; human-in-the-loop in Console; nested clusters exposed as agents | A project goal submitted in the Console is decomposed, delegated across a 5-role cluster, and delivered with a full replayable trace |

## 10. Testing strategy

- Unit tests for each component. Test-driven development throughout.
- Contract tests: run the A2A TCK against our inbound server. Our client is tested against SDK reference servers, and against 0.3 servers for compatibility.
- Integration tests: an in-process multi-agent network with fake LLMs, so they're deterministic.
- Fault injection: latency, dropped streams, 5xx errors, malformed cards, and restarts.
- Security tests: SSRF payloads, oversized/malicious parts, cycle attacks, tampered cards, and authz bypass attempts.

## 11. Decisions made (Claude's calls; user may override)

- Python 3.12 via `uv`, supporting 3.11 and up. `a2a-sdk>=1.2,<2`. Starlette/FastAPI. `httpx`. Pydantic v2. OpenTelemetry.
- Package and repo layout:
  - `src/a2agw/{core,serve,consult,security,context,adapters/*,cli,gateway}`.
  - Adapters are optional extras, for example `pip install a2agw[langgraph]`.
- One tool per partner by default. Discovery mode applies above 12 partners. `max_hops=8`.
- JSON-RPC is the default binding.
- The working name and the extension URI are placeholders.
- License: Apache-2.0, matching the A2A ecosystem. **This is unconfirmed.**

## 11a. Resolutions from builder review (Claude's calls; user may override)

1. **Multiple agents per process.** The core data model handles several agents per process from Phase 1.
   - An `AgentHost` mounts N agents, each with its own card, route prefix (`/agents/{id}/…`), optional `tenant`, policy, and task-store partition (`agent_id` column).
   - Embedded mode is simply the N=1 case. This avoids rewriting the serve layer when the shared gateway arrives.
2. **Outbound identity.** By default the agent calls partners with **its own per-partner service credential**. The original caller's identity travels in the call context (`on_behalf_of`, which is informational) and goes into the audit log.
   - Authorization covers "which callers may cause traffic to which partners".
   - OAuth token exchange (RFC 8693, on-behalf-of) is an optional `CredentialProvider` in Phase 2. The interface takes the inbound caller principal as a parameter from day one.
3. **Budget accounting.** The gateway enforces limits on **calls, hops, and deadlines**.
   - The adapter SPI gains an optional `Usage(tokens_in, tokens_out, cost)` event. Adapters that can extract usage (LangChain/LangGraph callbacks, OpenAI, Claude SDK) emit it.
   - Token and cost budgets are enforced only when usage is reported, and the card/registry says whether a given agent reports it.
   - The anti-goal is therefore met for calls and time everywhere, and for cost wherever usage is visible.
4. **Untrusted call context.** Loop protection works on a best-effort basis across the network, combined with **local guarantees that hold regardless of what callers send**:
   - Inbound values are clamped. Hop count is `max(received, 0)`, and the deadline is capped at the local maximum task duration. Budgets are capped at local per-caller limits.
   - Re-entry detection: the gateway records every `origin` and `contextId` it sent outbound. An inbound call that carries one of those, or that arrives during an active outbound chain for the same origin, counts as re-entry and is subject to policy.
   - Per-caller caps on concurrent tasks and fan-out bound the damage from partners that ignore the extension, such as A → P → A.
   - Phase 2 adds signed call contexts between our gateways (a JWS over the context) so hop and path can be trusted between cooperating gateways.
5. **Restart semantics.**
   - Inbound tasks that were `working` at restart are marked `failed` ("gateway restarted"). Their persisted outbound partner tasks are **canceled** (best effort) through the cancellation cascade.
   - Inbound tasks in `input-required` / `auth-required` remain resumable **only if** the adapter declares `durable_sessions=True`. For example, the LangGraph adapter with a checkpointer keyed by `contextId` qualifies.
   - Otherwise those tasks are failed at restart with a clear reason.
   - The outbound handle store exists for cancellation and audit, not for resuming work on behalf of a host run that no longer exists.
6. **Data classification.** The operator and agent supply it; the framework does not infer it.
   - It comes from a per-agent default, a per-partner allowed ceiling, and an optional `classification` argument or metadata on each call.
   - A pluggable `Classifier` hook is provided, with a simple regex PII detector included as an example that is off by default. No ML classifier is shipped.
7. **Receiving push notifications from partners.** This is out of scope for embedded mode. Outbound uses streaming, then resubscribe, then polling.
   - Sidecar mode (Phase 3) may add an optional authenticated webhook receiver.
   - Boundary condition 5's "dedupe of push events" applies to sidecar mode only. In embedded mode, deduplication covers streamed and polled events.

## 12. Left to the builder

- Internal module boundaries below the package level, and the exact class names.
- The embedding model and library for discovery-mode ranking. Keyword ranking is the default.
- The YAML config schema details.
- The exact structure of the conformance and chaos test harnesses.
