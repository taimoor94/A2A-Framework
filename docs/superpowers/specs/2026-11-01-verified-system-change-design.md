# Verified System Change (Phase 5) — Design

- **Date:** 2026-11-01
- **Status:** Approved 2026-11-01. Supersedes the Phase 4b (Console) and Phase 5 (clusters) entries of the 2026-10-25 design's §9 roadmap; everything else in that design stays binding.
- **Working name:** Verified System Change, "VSC". Package `a2agw.vsc`. Placeholder, Claude's call.
- **Depends on:** Phase 4a (control plane) as planned in `docs/superpowers/plans/2026-10-30-phase4a-control-plane.md`, which is in progress in another session and is not changed by this document.

## 1. Intent

The gateway (Phases 1–3) makes agents from any framework talk to each other safely. Phase 4a adds the control plane. Neither does work. This phase makes the gateway **deliver** work: one request becomes a coordinated, test-proven change across every connected system it touches, with a receipt that proves what was done.

The reason, from the 2026-11-01 research (`scratchpad/reports/Agentic orchestration startup landscape.md`, to be copied into `docs/research/` when committed):

- Every coding-agent vendor treats one pull request in one repository as the unit of work. On the only rigorous cross-repository benchmark (WideSWE, arXiv 2609.33382) the best agent solves **42.5%** of tasks; 59% of its failures pass tests but behave wrongly, 38% miss a repository that needed a change.
- Running one agent per repository independently made feature delivery **worse** (43.3% → 31.7%) at 3.1× the API calls. Coordination with a shared specification and whole-system checks is the missing piece, not more agents.
- Under equal token budgets, single agents match or beat almost every multi-agent design (BenchAgent 2606.05670, Tran & Kiela 2604.02460). Verification by execution is the reliable lever (best-of-N with tests: 55.0% → 68.2% on SWE-bench Verified). LLM judges are unreliable on code.
- Enterprises are stuck in pilots (5–10% in production) because they cannot govern or verify agents. Only 6.6% of developers would trust AI with an important decision; nearly half trust output they can verify.

So the product is not "smarter agents". It is **the only system that can prove a change is correct across everything it touches**, measured, billable and auditable. The gateway's existing parts (adapters, sidecar, limits, policy, hash-chained audit) are the foundation of the receipt.

**First proof** (the user's decisions, 2026-11-01): two corpora, both inside this repository, no outside project needed.

1. **This repository's own systems.** A "system" is a declared sub-tree with its own gate and tests, not necessarily a repository: this repository already holds four connected systems in three languages, the Python core (`src/a2agw`), the Node sidecar agent (`examples/node_coder`), the Docker/compose deployment (`examples/docker`, `Dockerfile`) and the sidecar contract (`docs/sidecar.md`), joined by the integration tests. 27 past commits changed the core together with an example or the contract, so tasks can be mined from history.
2. **A realistic multi-repository demo estate, built by the builder** under `examples/vsc_estate/`: three small services that depend on each other the way real systems do, each its own git repository when the demo runs (initialised by a script, so the estate tests true cross-repository workspaces, contracts and whole-system checks): an **orders API** (Python, Starlette, SQLite), an **inventory service** (Node, standard library) and a **shared contract** repository (OpenAPI for both, plus a contract test suite that runs the two services together). The scenarios are real engineering requests, each touching two or three repositories, with acceptance tests written as they would be in a real team: for example "reserve stock when an order is placed, release it when it is cancelled" (orders + inventory + contract), "add an idempotency key to order creation" (orders + contract), "inventory must report backorders, and orders must show them" (all three), "rename `qty` to `quantity` in the contract" (all three, a pure ripple change). At least 10 such scenarios form the estate corpus; the rest of the ≥20 tasks come from corpus 1.

Every change the system delivers on either corpus is a benchmark case, a cost data point and a demo. The published result that makes the company fundable, on public cross-repository tasks, follows in 5b when the user's other projects and the WideSWE subset are added.

## 2. Goals

1. **One request → one verified change across N repositories and systems.** Input: a request in natural language (plus optional attachments). Output: branches or pull requests in every affected repository, a passing whole-system check, and a receipt.
2. **Verification by execution, ranked.** Project CI and type checks → reproduction tests that fail before and pass after → regression filters → cross-repository contract tests → LLM review, advice only. A job is "accepted" only when every executable check passes.
3. **A receipt.** A hash-chained, exportable, offline-verifiable record of the job: the request, the executable specification, the plan, every agent call, every check with its result, the diffs. Built on the existing `AuditLog` chain.
4. **One coordinator, many workers.** One planner holds the plan and the decision log. Workers are existing coding agents (Claude Code, Codex CLI, OpenHands SDK, OpenCode, Gemini CLI) run through the gateway's sidecar adapters, in isolated workspaces, each with the shared specification. Helper agents fan out only for read-only scouting.
5. **A system map.** A cross-repository graph of how the connected systems depend on each other (services, APIs, schemas, configs, vendor integrations), built from code (tree-sitter, SCIP) and from what each delivered job learns. No open-source equivalent exists; it compounds with use.
6. **Budgets that fail closed.** Tokens, cost, time and attempts per job and per step, enforced through the existing call-context and `Usage` machinery.
7. **A benchmark.** An internal suite of real multi-repository tasks from the user's projects plus a public WideSWE subset, run at matched token budgets against a single-agent baseline, with the method published.
8. **Operable through what exists.** Jobs are A2A tasks on the host, so they are visible, cancellable and approvable through the gateway admin API and the Phase 4a control plane with no new control surface.

## 3. Non-goals

- The Console web UI (former Phase 4b). It comes after the benchmark result, against the 4a and VSC APIs.
- The cross-company trust network (delegation contracts, receipts exchanged between organisations, reputation). The receipt and identity formats are designed so that can follow, but nothing is built for it here.
- Self-modifying agents at runtime. Self-tuning is offline only (§7.9).
- Running or hosting customers' infrastructure; multi-tenant SaaS hardening (E2B sandboxes, SOC 2 controls) is Phase 5c, after a paying design partner exists.
- Being a coding agent. Workers are rented, interchangeable, and plugged in through the sidecar.
- gRPC, as before.

## 4. Anti-goals

The phase fails, even if it technically works, if any of these happen:

- A job is reported "accepted" on the word of an LLM judge, or without the cross-repository check running.
- A worker makes a change without the shared executable specification, or two workers edit the same repository in one job.
- Content from a worker's output, a repository, a partner agent or a request can trigger a merge, a deploy, a secret read or an outbound send without passing the gate.
- The receipt cannot be verified offline, or omits a call, a check or a diff.
- Cost per accepted change is unknown. Every job records tokens, cost and wall time.
- Features ship before the benchmark harness and the single-agent baseline exist.
- The core imports an agent framework, or `a2agw.vsc` is required to run a plain gateway.

## 5. Constraints

- Everything in the 2026-10-25 design's §5 and §11/§11a still holds: Python 3.11+, `a2a-sdk` 1.x, Starlette, SQLAlchemy Core on SQLite or PostgreSQL, OpenTelemetry, Apache-2.0.
- **Licences.** Only MIT, Apache-2.0 or BSD parts may be built on: OpenHands SDK, mini-SWE-agent, Codex CLI, OpenCode, tree-sitter, SCIP, Graphiti, DBOS, Temporal, Hatchet, E2B infra, Langfuse core, Inspect, GEPA/DSPy. Never: Restate (BSL), Inngest server (SSPL), Arize Phoenix (ELv2), Daytona (AGPL, archived), new-api (AGPL), nor the `enterprise/` or `ee/` directories of LiteLLM, Langfuse and OpenHands. OmniRoute (MIT) is a source of ideas only, never a dependency.
- **Phase 4a is not modified.** VSC uses its results: `a2agw.ops.actions` for writes, the bus and audit for reporting, control-plane commands for cancel and approve. Where VSC needs a 4a hook that does not exist, it adds one additively in its own plan after 4a lands.
- **5a starts now, on a worktree branched from `main` at 323d659** (4a Task 1, `a2agw.ops.actions`, is committed there); it does not wait for the rest of 4a. Nothing in 5a depends on 4a Tasks 2–12; the admin task routes and metrics are used only in the final wiring step, which rebases onto whatever 4a has merged by then. The control-plane view of jobs and receipts (§7.10) is wired after 4a merges, as an additive step at the end of the 5a plan.
- **Workers are external processes.** Claude Code, Codex CLI and friends run as stdio or webhook sidecar agents, never imported. The OpenHands SDK may be used in-process behind an extra, like any adapter.
- **Models.** The planner uses the strongest available model (Claude Opus 5.5 at the time of writing, through the Claude Agent SDK adapter); workers use whatever the chosen CLI agent uses; retries escalate from cheaper to stronger ("try cheap, check, escalate"). Prompt prefixes are structured for caching.
- **The user's machine is slow with Defender active.** Long gates run in the background, uncapped.
- **Two sessions share this repository today.** This document touches only `docs/`. Implementation starts in its own worktree after Phase 4a merges.

## 6. Approaches considered

### 6.1 Where the orchestrator lives

| | Approach | Trade-off |
|---|---|---|
| **A (chosen)** | **A VSC job runner owns the job; the planner is an A2A agent on the host** (`AgentSpec(id="deliver")`) that the runner invokes in short turns, one per decision. A job is a VSC entity (`vsc_jobs`), exposed to A2A callers as a task of `deliver` whose `contextId` is the job id. Approval is `input-required`; cancel is the existing cascade; the receipt spans the job, not one task. | Reuses every existing guarantee (limits, policy, audit, control plane, TCK conformance) without changing the core's binding restart rule (§11a.5 of the earlier design: `working` tasks fail at restart). A job that outlives its task, or a gateway restart, continues as a **new task in the same `contextId`**; the receipt keys on the job id and lists every task. Each planner turn stays well under the host's task deadline. |
| B | A separate `a2agw-vsc` service with its own API, calling the gateway. | Cleaner separation, but a second control surface, a second audit trail and a second auth model: exactly what Phase 4a's "one implementation, one audit trail" rule forbids. |
| C | A LangGraph graph in the demo style (`examples/software_team`). | Fast to start; ties the product's core to one framework, against the anti-goal. The demo stays a demo. |

### 6.2 Coordination model

| | Approach | Trade-off |
|---|---|---|
| **A (chosen)** | **One coordinator, workers split along repository boundaries, explicit interface contracts, whole-system check at the end.** | Matches the evidence (MAST, BenchAgent, WideSWE). Serial where repositories depend on each other, parallel where they do not. |
| B | A swarm of peer agents negotiating. | Higher token cost, lower accuracy in every controlled study found. Rejected. |
| C | A single agent with every repository in one workspace. | The strongest baseline, and the one VSC must beat at matched budget. Kept as the benchmark control, not the product: it does not scale past a few repositories or across organisations. |

### 6.3 Durability of long jobs

| | Approach | Trade-off |
|---|---|---|
| **A (chosen for 5a)** | **A `vsc_jobs` / `vsc_steps` table in the gateway's store** (SQLAlchemy Core, SQLite and PostgreSQL), each step idempotent and checkpointed; resume on restart replays from the last completed step. | No new dependency; works on the user's laptop with SQLite; same `retry_ddl` migration pattern as everything else. Costs: no distributed workers until 5c. |
| B | DBOS (MIT, PostgreSQL only). | The lightest proper durable-execution engine for Python; adopt in 5c when jobs run on several machines. PostgreSQL-only blocks the SQLite dev path today. |
| C | Temporal (MIT). | Strongest, heaviest; another server to run. Only if 5c needs cross-language workers. |

### 6.4 Verification gate

| | Approach | Trade-off |
|---|---|---|
| **A (chosen)** | **Ranked executable checks; the LLM reviewer advises only; best-of-N retries happen only after a failed check, capped by budget.** | Follows the evidence; costs tokens only on failure. |
| B | LLM judge as the primary gate. | Measured 4.4% accuracy as a multi-agent judge; over-correction bias. Rejected. |
| C | Always sample N candidates and pick by tests. | +13 points on SWE-bench Verified, but N× cost on every job. Used selectively (A), not by default. |

## 7. Architecture

```
 request (CLI / A2A / control-plane command)
     │
     ▼
 ① INTAKE      request → executable specification: acceptance tests, API/schema
     │          contracts, affected-systems list (proposed from the system map)
     ▼
 ② SYSTEM MAP  cross-repo graph: repos, services, endpoints, schemas, configs,
     │          vendor APIs; who calls whom; built by indexers, enriched by jobs
     ▼
 ③ PLANNER     one coordinator (A2A agent "deliver"): plan = ordered steps per
     │          repository with interface contracts; decision log; budgets
     ▼
 ④ WORKERS     one coding agent per repository, in its own workspace, given the
     │          shared spec + its contract; sidecar (stdio/webhook) or OpenHands SDK
     ▼
 ⑤ VERIFIER    ranked checks per repo, then the whole-system check (contract
     │          tests across repos); failure → bounded retry / escalate
     ▼
 ⑥ GATE        human approval only at irreversible steps (merge, deploy,
     │          migration): A2A input-required, answered via admin/control plane
     ▼
 ⑦ RECEIPT     job record on the audit chain: spec hash, plan, calls, checks,
                diffs, usage; exportable; verifiable offline
```

### 7.1 Package layout

```
src/a2agw/vsc/
  __init__.py        import guard for the `vsc` extra
  spec.py            ExecutableSpec: request, acceptance tests, contracts, affected systems
  intake.py          request → ExecutableSpec (planner-assisted; human can edit)
  sysmap/            indexers (tree-sitter, SCIP), graph store, queries
  planner.py         the "deliver" agent: plan, decision log, step dispatch
  workers.py         worker registry: how each coding agent is launched and given a task
  workspace.py       per-repository isolated checkouts (git worktrees in 5a; E2B in 5c)
  verify.py          ranked checks, whole-system check, retry policy
  gate.py            approval points; maps to NeedInput and control-plane commands
  receipt.py         job receipt: build, export, verify
  store.py           vsc_jobs, vsc_steps, vsc_receipts tables
  bench/             benchmark harness: task corpus, matched-budget runner, report
```

### 7.2 Intake and the executable specification

- `ExecutableSpec` holds: the original request (verbatim, untrusted), a normalised statement of done, **acceptance tests** (runnable, per affected repository and one whole-system suite), **contracts** (OpenAPI/JSON Schema/type signatures for every cross-repository interface the change touches), the affected-systems list, and budgets.
- The planner drafts it with help from the system map; the operator may edit it before work starts (an `input-required` step, skippable by policy for low-risk requests).
- The spec is hashed; the hash goes in the receipt. A job's "accepted" claim always refers to a specific spec hash.
- Spec-driven development has no measured benefit yet (research §4); the spec exists here because it **is** the verifier, not as a document.

### 7.3 System map

- Nodes: repository, package, service, endpoint, schema/table, config key, vendor API, queue/topic, agent. Edges: imports, calls, publishes/consumes, reads/writes, deploys-to, owned-by.
- Sources, in order: SCIP indexes where a language has an indexer; tree-sitter for the rest; declared configs (OpenAPI files, docker-compose, Terraform, package manifests); and **job learnings**: every delivered job records which edges it touched or discovered.
- Stored in the gateway store (tables, not a graph database) in 5a; Graphiti (Apache-2.0) is an option in 5b if temporal queries are needed.
- Queries the planner uses: affected systems for a request; callers of an endpoint; schema consumers; cross-repository paths.
- This is the moat. It is also untrusted input to the planner (repository content can contain injected text): see §7.8.

### 7.4 Planner

- An `AgentSpec(id="deliver", ...)` served by the host through `ClaudeAgentAdapter` (strongest model). Its tools, via `host.partner_tools` and local tools: query the system map, dispatch a step to a worker, run a check, request approval, write the decision log.
- Holds exactly one plan: ordered steps, each bound to one repository and one contract set, with dependencies. Independent steps run in parallel; dependent ones serially.
- Scouting (read-only exploration of a repository) may fan out to cheap helper agents; **no helper writes**.
- Every decision is logged with its reason (the receipt needs it; the self-tuning loop in §7.9 learns from it).

### 7.5 Workers and workspaces

- A worker is a `WorkerSpec`: how to launch (stdio command, webhook URL, or in-process OpenHands SDK), the model it uses, its cost class, its capabilities (languages, test runners). The first registered workers: Claude Code (`claude -p` as stdio), Codex CLI, OpenHands SDK; OpenCode and Gemini CLI follow.
- **Workers are not hosted A2A agents in 5a.** The job runner launches one `StdioAdapter` (or `WebhookAdapter`) instance per step, with `cwd` set to the step's workspace, outside the host's agent table (the host refuses new agents after startup, and a hosted stdio agent has one fixed process and directory). The runner wraps every worker call: it records an audit row and the usage, applies the step's deadline and budget, and hands the worker a consult grant from the host's `GrantIssuer` so the worker reaches partners through `/a2agw/v1` exactly as a sidecar agent does today. That wrapper is what makes "every agent call" in the receipt true.
- Each step runs in an isolated workspace: a git worktree on a dedicated branch in 5a; an E2B Firecracker sandbox with an egress allowlist in 5c. A worker sees only its repository, the shared spec and its contract.
- Workers consult partners (other agents) only through the gateway's REST/MCP sidecar with a per-turn consult token, as today; they never hold credentials.
- **Budgets are enforced by `a2agw.vsc`,** not by the core: the runner sums `Usage` from workers and the planner against the job's token and cost budget and the step's share of it, and stops the job (`failed`, reason `budget`) when exceeded. The core's call context keeps enforcing calls, hops and deadline unchanged. A worker that reports no usage (some CLI modes) runs under time and attempt caps only, and the receipt marks its usage `unreported`; a job may be configured to refuse such workers. How a job budget is split across attempts is the builder's.
- Durable steps: `vsc_steps` rows with state, worker, workspace, usage, result hash; a restart resumes from the last completed step and discards half-done worktrees.

### 7.6 Verifier

Per repository, in order; any failure stops the step:
1. The project's own gate (lint, type check, CI command from the repo's config).
2. Reproduction tests from the spec: must fail on the base commit and pass on the change.
3. The project's existing test suite (regression).
4. Contract checks: the repository's side of every contract in the spec.

Whole-system, after every step passed: the cross-repository acceptance suite, run against all changed branches together (compose or a declared integration runner).

Then, advisory only: an LLM review that annotates risks; it cannot fail a job on its own.

Retry policy: a failed check returns the failure to the same worker once; a second failure escalates to a stronger worker/model; a third failure samples up to N (budgeted) candidates and keeps the first that passes; then the job stops in `failed` with the receipt stating why. Every attempt is recorded with its cost.

### 7.7 Gate and receipt

- Irreversible actions (merge, deploy, data migration, outbound sends, secret access) are **plan steps of a distinct kind** that always pause in `input-required` unless the `vsc:` policy section allows auto-approval for that repository and action (a VSC section of the policy file, not a change to the core `Policy` schema). Approval arrives as an A2A reply, through the admin API, or as a Phase 4a control-plane command.
- **5a delivers local branches.** The result of a job is one branch per repository in its workspace, plus an optional `merge` gate step that fast-forwards a declared target branch locally. Pushing to a forge, opening pull requests and merging there need a forge client and credential references: Phase 5b.
- **Editing the specification at intake** uses a VSC admin route, `PUT /a2agw/admin/vsc/jobs/{id}/spec` (JSON, with the same admin header and scope rules as other admin writes), and `a2agw vsc spec edit <job>` in the CLI; the `input-required` answer only confirms or rejects. The 32 KiB text answer is too small and unstructured for a spec.
- Submitting a job and approving an irreversible step need the `a2agw:vsc` scope (new); `a2agw:admin` implies it. The control plane maps its roles onto it in 5c.
- The receipt is assembled from the task's audit rows plus the `vsc_receipts` row: spec hash, plan, each step's worker, usage and result, each check's command, exit status and log hash, each diff's hash, every approval with its principal. `a2agw vsc receipt export <job>` writes a JSON bundle; `a2agw vsc receipt verify <bundle>` recomputes the chain offline, like `audit verify` today.

### 7.8 Security

- **Plan-then-execute.** The planner's plan (which repositories, which actions) is fixed before workers run; worker output, repository content and partner replies can refine *content* within a step but cannot add actions, repositories or privileged steps. This is the CaMeL-style separation the research recommends.
- Pin and diff tool and worker descriptions the way partner cards are pinned today; a changed description quarantines the worker.
- Workspaces have no credentials; pushes and merges happen only in the gate, by the gateway, with its own credentials.
- An injection test suite ships with 5a: tasks whose repositories and requests contain instructions aimed at the agents; the receipt must show none of them triggered an action.
- The untrusted-text envelope and the 64 KiB cap apply to everything workers and scouts return.

### 7.9 Learning and self-tuning (offline)

- Every job's spec, plan, decisions, checks and outcome become a case in the internal benchmark corpus.
- The planner's prompts and retry policies are tuned offline with GEPA/DSPy against a held-out part of the corpus, with reward hacking checks (the Darwin Gödel Machine faked its own logs). Nothing tunes itself at runtime.

### 7.10 Interfaces with Phase 4a

- Jobs appear as tasks of the `deliver` agent in the control plane's views; cancel and approval go through 4a commands to `a2agw.ops.actions`.
- Receipts are reachable through the gateway admin API (`GET /a2agw/admin/vsc/jobs/{id}/receipt`) and forwarded to the control plane like audit rows.
- Metrics from 4a's `GatewayMetrics` gain VSC counters: jobs by state, acceptance rate, cost per accepted change, wall time.

### 7.11 Declaring the connected systems

- A `vsc:` section of `a2agw.yaml` declares the systems a gateway may work on. A system is a repository, or a sub-tree of one (`path`), with its own gate and tests; several systems may share a repository and are then checked out in one worktree per job:

  ```yaml
  vsc:
    systems:
      - id: core
        repo: .                                         # local path, or a clone URL
        path: src/a2agw                                 # optional sub-tree
        default_branch: main
        gate: [uv, run, ruff, check, src]               # the system's own gate
        tests: [uv, run, pytest, -q, tests/serve, tests/adapters, tests/gateway]
        index: [python]                                 # indexers for the system map (5b)
      - id: node-coder
        repo: .
        path: examples/node_coder
        gate: [node, --check, examples/node_coder/agent.mjs]
        tests: [uv, run, pytest, -q, tests/integration/test_webhook_agent.py]
      - id: sidecar-contract
        repo: .
        path: docs/sidecar.md
      - id: billing-api                                 # a later, separate repository
        repo: git@github.com:acme/billing-api.git
        default_branch: main
        gate: [npm, run, lint]
        tests: [npm, test]
    checks:
      - id: sidecar                                     # a whole-system check
        systems: [core, node-coder, sidecar-contract]
        run: [uv, run, pytest, -q, tests/integration/test_phase3_demo.py]
      - id: core+billing-api
        systems: [core, billing-api]
        run: [docker, compose, -f, integration/compose.yaml, run, tests]
    budgets: {tokens: 2000000, cost_usd: 50, attempts: 3, deadline_s: 7200}
  ```

- Paths are relative to the config file like every other path. A clone URL is fetched through the guarded client. The whole-system check is a declared command (compose is the common case, not a requirement). Contract drift (§8.8) re-runs the system's indexers and the check. Workers are confined to their system's `path` by instruction and by the verifier (a diff outside the step's system fails the step); OS-level confinement comes with sandboxes in 5c.

### 7.12 Benchmark harness

- `a2agw.vsc.bench` holds a corpus of real tasks, each a request, a base commit per repository and an acceptance suite that fails before and passes after. **5a tasks are mined from this repository's git history:** a past commit set that touched two or more declared systems (core plus the Node agent, the Docker example or the sidecar contract; 27 such commits exist) becomes a task (request = the commit messages or linked issue, base = the parent commits, acceptance = the tests those commits added, run against the pre-change tree). The builder writes the mining tool; the user picks which projects (§12). Tasks the mining cannot produce are authored by hand.
- The WideSWE public subset is **Phase 5b**: its repositories need per-task environments in several languages, which is harness work of its own.
- Runner modes: `single` (one agent, all repositories in one workspace) and `vsc`. The `single` baseline is Claude Code with every affected repository checked out in one workspace and the same instructions; its token budget is set to what the `vsc` run of the same task used (or a fixed cap when the `vsc` run failed on budget). Both report solve rate, tokens, cost, wall time, and the failure class (missed repository, passes-tests-but-wrong, timeout, budget).
- The published result compares the two at a matched budget. Until the harness and the baseline run exist, no other 5a feature is "done".

## 8. Boundary conditions to handle explicitly

1. **A repository needs a change the spec did not list.** The planner may propose adding it; the plan changes only through the gate (an approval), never on a worker's say-so.
2. **Two steps need the same repository.** Serialised; one workspace per repository per job.
3. **The whole-system check fails after every repository passed.** The job returns to planning with the failure, bounded by the retry policy; the receipt records every round.
4. **A worker process dies or hangs.** The existing stdio supervision restarts it; the step resumes from its checkpoint with a fresh workspace.
5. **Gateway restart mid-job.** `vsc_steps` resume; half-done worktrees are discarded; approvals already given stay given.
6. **Budget exhausted.** The job ends `failed` with the receipt stating the budget and where it went; partial branches are kept for a human.
7. **The request or a repository contains instructions for the agents.** Plan-then-execute and the gate make them inert; the injection suite proves it.
8. **Contract drift**: a repository's interface changed since the map was indexed. The contract check fails, the map is re-indexed, and the planner re-plans.
9. **A worker's model or CLI is unavailable.** Escalate to another registered worker with the same capabilities; record the substitution.
10. **Secrets in repositories or logs.** The existing secret-hygiene rules apply to receipts: hashes of logs, never log text with credentials; the exporter redacts by the same rules as the audit export.

## 9. Phasing

| Phase | Scope | Done when |
|---|---|---|
| **5a. Core on own projects** | `a2agw.vsc`: `vsc:` config, job runner and durable steps, spec, planner, workers (Claude Code, Codex CLI, OpenHands SDK), worktree workspaces, ranked verifier, local merge gate, receipt, injection suite, corpus mining, benchmark harness with the single-agent baseline | VSC delivers a real change across the three repositories of the demo estate end to end as local branches, with the whole-system contract check passing and an offline-verified receipt; it also delivers a change across two declared systems of this repository; and the harness reports a matched-budget comparison against the single-agent baseline on ≥20 tasks (≥10 estate scenarios plus tasks mined from this repository's history) |
| **5b. System map and contracts** | tree-sitter/SCIP indexers, map store and queries, job learnings, contract checks across repositories, failure-class reporting | On the corpus, the missed-repository failure class drops below 10% of failures, and the published result shows VSC ≥ single-agent solve rate at matched budget (target ≥55% on the WideSWE subset) |
| **5c. Customer-ready** | E2B sandboxes, DBOS or Temporal for distributed steps, multi-worker scale-out behind agentgateway, cost reporting per customer, SOC 2 control mapping, Console (former 4b) against 4a + VSC APIs | One paying design partner runs a job on their systems with a receipt their reviewers accept |

## 10. Testing strategy

- Unit tests per module; every worker is faked in tests (a scripted stdio agent, as in `tests/adapters/stdio_agent.py`); no real model in the gate.
- Integration tests run a job across two fixture repositories in-process, including a failing whole-system check, a restart mid-job, a budget exhaustion and an injection attempt.
- The benchmark harness is the only place real models run; it runs manually and in a scheduled job, never in the CI gate.
- The existing gate stays: `uv run pytest -q -W error`, `ruff`, TCK MUST at 0 failures, crewai script.

## 11. Decisions made (Claude's calls; user may override)

- A VSC job runner owns jobs; the planner is an A2A agent on the host invoked in short turns; a job that outlives a task or a restart continues as a new task in the same `contextId` (§6.1 A). The core's restart and deadline rules are unchanged.
- Workers are per-step `StdioAdapter`/`WebhookAdapter` instances launched by the runner, not hosted agents; the runner's wrapper records audit and usage and hands out consult grants (§7.5).
- Token and cost budgets are enforced by `a2agw.vsc` from collected usage; the core enforces calls, hops and deadline as before (§7.5).
- 5a delivers local branches and a local fast-forward merge gate; forge pushes and pull requests are 5b (§7.7).
- Connected systems are declared in a `vsc:` section of `a2agw.yaml` (§7.11).
- The 5a corpus is mined from the user's projects' git history; WideSWE is 5b (§7.12).
- Spec editing is a VSC admin route and CLI command; auto-approval rules live in a `vsc:` policy section; a new `a2agw:vsc` scope gates job submission and approvals (§7.7).
- 5a starts after 4a's Tasks 1–3 are committed, not after all of 4a (§5).
- A receipt is bound to the audit chain by an audit row that carries the receipt hash (builder's detail).
- Durability in 5a is a step table in the gateway store (§6.3 A); DBOS in 5c.
- Workspaces are git worktrees in 5a, E2B in 5c.
- The planner model is Claude Opus 5.5 through `ClaudeAgentAdapter`; the first workers are Claude Code, Codex CLI and the OpenHands SDK.
- The system map lives in store tables, not a graph database, until queries need more.
- The Console is deferred to 5c and built against stable APIs.
- The first proof corpus comes from the user's own projects; the public WideSWE subset is added for comparability.
- Pricing instrumentation (tokens, cost, wall time per accepted change) is recorded from 5a, because the business model bills per accepted change.

## 12. Left to the builder

- Exact table schemas for `vsc_jobs`, `vsc_steps`, `vsc_receipts` and the map.
- The `WorkerSpec` launch contract for each CLI agent (flags, non-interactive modes, how results are read back).
- The whole-system check runner for projects without compose (a declared command is the fallback).
- The receipt bundle format beyond "JSON, hash-chained, verifiable with the existing audit tools".
- Which WideSWE tasks form the 5b public subset.
- The git-history mining tool for the corpus (§7.12) and the hand-authoring format for tasks it cannot produce.
- The user has chosen this repository plus a builder-made demo estate for the first proof; the exact system boundaries (§7.11), the estate's code and its scenarios are the builder's, and the user's other projects are added to `vsc.systems` when named.
- **Status:** approved by the user on 2026-11-01 ("work yourself by making dummy projects and work across them, on real scenarios").
- The intake prompt and plan format; these are the first targets of offline tuning.
