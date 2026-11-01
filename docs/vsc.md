# Verified System Change

Verified System Change (VSC, package `a2agw.vsc`) makes the gateway deliver work. One request
in natural language becomes a coordinated, test-proven change across every connected system it
touches: one branch per repository, a passing whole-system check, and a receipt that proves
what was done. The planner writes an executable specification and a fixed plan; rented coding
agents (Claude Code, Codex CLI, OpenHands, ...) make the change one system at a time in
isolated git worktrees; ranked executable checks decide whether each step and the whole system
pass (an LLM never does); irreversible steps wait for a human; and the job's record is bound to
the gateway's hash-chained audit log, exportable and verifiable offline.

This is the reference for operators and developers. Phase 5a (this release) delivers local
branches on local repositories; [Known limitations](#known-limitations) lists what it does not
do yet. The design is `docs/superpowers/specs/2026-11-01-verified-system-change-design.md`.

- [Install](#install)
- [Configuration](#configuration)
- [How a job runs](#how-a-job-runs)
- [The `deliver` agent over A2A](#the-deliver-agent-over-a2a)
- [Admin API](#admin-api)
- [CLI](#cli)
- [Workers](#workers)
- [Budgets and the retry policy](#budgets-and-the-retry-policy)
- [The gate and `auto_approve`](#the-gate-and-auto_approve)
- [Receipts](#receipts)
- [The benchmark](#the-benchmark)
- [The injection suite](#the-injection-suite)
- [Security notes](#security-notes)
- [Known limitations](#known-limitations)

## Install

```bash
uv add "a2a-gateway[vsc]"      # the Claude planner (claude-agent-sdk); not needed for planner: scripted
```

A plain gateway never imports `a2agw.vsc` beyond its config model: VSC is switched on by a
`vsc:` section in `a2agw.yaml`, and `a2agw serve` then adds two agents (`deliver` and
`vsc-planner`) and the routes under `/a2agw/admin/vsc`. The section needs at least one worker.
VSC needs a database (`db_url`) and, for receipts, the audit log.

## Configuration

### This repository's own section

The worked example is this repository: four connected systems in three languages, joined by
the integration tests. The test `tests/integration/test_vsc_self.py` loads this block, points it
at a throwaway clone and runs a job with it. What it executes: the `core`, `node-coder` and
`sidecar-contract` systems (gates, path confinement; `core`'s tests narrowed to
`tests/gateway/test_protocol.py` for speed), the `sidecar` check, and the `python` substitution
(`python` becomes the test's interpreter). Documented only: the `docker` system, the `compose`
check, `core`'s full test list, the `workers` block and `budgets` (the test uses its own
scripted worker and the budgets as written). For those the test checks shape only: `docker` and
`compose` parse into `VscConfig` and every path they reference exists in the clone.

<!-- vsc-self-config: tests/integration/test_vsc_self.py parses the next yaml block -->
```yaml
vsc:
  systems:
    - id: core
      repo: .
      path: src/a2agw
      default_branch: main
      # --no-cache / -p no:cacheprovider keep tools from writing cache files into the workspace
      gate: [python, -m, ruff, check, --no-cache, .]
      tests: [env, PYTHONPATH=.., python, -m, pytest, -q, -p, no:cacheprovider,
              ../../tests/gateway, ../../tests/serve, ../../tests/adapters]
      index: [python]
    - id: node-coder
      repo: .
      path: examples/node_coder
      default_branch: main
      gate: [node, --check, agent.mjs]
      tests: [env, PYTHONPATH=../../src, python, -m, pytest, -q, -p, no:cacheprovider,
              ../../tests/integration/test_phase3_demo.py, -k, node_coder]
    - id: sidecar-contract
      repo: .
      path: docs/sidecar.md
      default_branch: main
    - id: docker
      repo: .
      path: examples/docker
      default_branch: main
      tests: [env, PYTHONPATH=../../src, python, -m, pytest, -q, -p, no:cacheprovider,
              ../../tests/test_examples_docker.py]
  checks:
    - id: sidecar
      systems: [core, node-coder, sidecar-contract]
      run: [env, PYTHONPATH=src, python, -m, pytest, -q, -p, no:cacheprovider,
            tests/integration/test_phase3_demo.py]
      timeout_s: 600
    - id: compose
      systems: [core, docker]
      run: [env, PYTHONPATH=src, python, -m, pytest, -q, -p, no:cacheprovider,
            tests/test_examples_docker.py]
  workers:
    - id: claude-code
      command: [python, /opt/vsc-bridges/claude_code.py]   # your bridge, see Workers
      model: claude-opus-5-5
      cost_class: strong
      env: {ANTHROPIC_API_KEY: "${ANTHROPIC_API_KEY}"}
      timeout_s: 1800
  budgets: {tokens: 2000000, cost_usd: 50, attempts: 3, deadline_s: 7200}
  planner: claude
  workspace_dir: .a2agw/vsc
```

Notes on this section, which apply to any other:

- **Where commands run.** A system's `gate`, `tests` and acceptance tests run in its `path`
  sub-tree of the job's workspace (so `core`'s commands run in `src/a2agw/`); a whole-system
  check runs at the root of the **first** listed system's workspace, with `VSC_WS_<ID>` (the
  system id upper-cased, other characters as `_`) naming every workspace of the check. A worker
  runs at the workspace root. A system whose `path` is a file (`sidecar-contract`) cannot have a
  gate or tests of its own (they would run in a file); the `sidecar` check covers it.
- **No shell.** Commands are argument lists, run directly. `python` and `node` resolve on the
  allowlisted `PATH`: run the gateway from the virtual environment that has the project's
  dependencies (for example `uv run a2agw serve`), so `python` is that environment's.
- **Test the workspace's code, not the installed one.** In this repository `a2agw` is installed
  in editable mode from the main checkout, so every Python command puts the workspace's `src`
  first with `env PYTHONPATH=...`. Do not use `uv run` inside a workspace: uv would build a new
  virtual environment from the workspace's `pyproject.toml` on every job.
- **Several systems, one repository.** All four systems share `repo: .`, so a job has one
  worktree and one branch for them, `vsc/<job id>/<repository id>`, with one commit per passed
  step; a step's diff outside its own `path` fails it (`path_confinement`). The root
  `Dockerfile` belongs to no system here, so no job may change it; declare it as a system
  (`path: Dockerfile`) to let one.
- **Workspaces** live under `workspace_dir`, relative to the config file (default
  `.a2agw/vsc`; `.a2agw/` is in this repository's `.gitignore`). Paths (`repo`, `workspace_dir`)
  are relative to the config file. `repo` must be a local path: clone URLs are refused (5b).
- `index` is accepted for the system map of Phase 5b and is not used yet.

### Reference

| Key | Meaning |
|---|---|
| `systems[]` | `id` (`[a-z0-9][a-z0-9-]*`), `repo` (local path), `path` (sub-tree, default `.`), `default_branch` (default `main`), `gate`, `tests` (commands, optional), `index` (5b) |
| `checks[]` | whole-system checks: `id`, `systems` (two or more), `run` (command), `timeout_s` (default 1800). A job runs every check that names a system it edits (systems it does not edit take part at their base). A spec or plan of two or more systems is refused unless checks cover each of them together with another |
| `workers[]` | `id`, `command`, `model`, `cost_class` (`cheap`, `standard`, `strong`), `reports_usage` (default true), `env` (added to the worker's environment), `timeout_s` (default 1800) |
| `budgets` | `tokens` (2 000 000), `cost_usd` (50), `attempts` (3, per step), `deadline_s` (7200, active time) |
| `planner` | `claude` (default; the `vsc-planner` agent through the Claude Agent SDK) or `scripted` (deterministic, for tests and demos: one edit step per system, the request as instructions) |
| `workspace_dir` | where job worktrees go (default `.a2agw/vsc`) |
| `auto_approve[]` | `{system, action}` pairs (`action`: `merge`, `deploy`, `migrate`, `send`) that skip the human gate; a `merge` rule also names its `target_branch` (required) and covers only that branch |
| `require_spec_review` | pause every job after intake in `awaiting_spec` until the spec is confirmed or edited with `PUT /jobs/{id}/spec` (default false) |
| `approvers[]` | principal ids (`key:ops`, `jwt:alice`) whose approvals count; empty (default): anyone but the job's owner. Admins (`a2agw:admin`) may always approve |
| `allow_self_approval` | let a job's owner approve its own privileged steps when `approvers` is empty (default false; required without `auth`) |
| `merge_targets[]` | branches a `merge` step may target besides each system's `default_branch` (default none) |

VSC needs `auth`: a gateway without it refuses to attach VSC unless both `admin_without_auth:
true` and `vsc.allow_self_approval: true` are set (development only; every caller is then
`anonymous`, owner and approver alike). An API key may not use the principal id
`vsc-internal` (reserved for the planner's caller).

`examples/vsc_estate/a2agw.yaml` is the second worked example: three repositories (Python,
Node, an OpenAPI contract) and a whole-system contract suite; see its README.

## How a job runs

The stages of the design, and what 5a does in each:

1. **Intake.** The planner turns the request into an `ExecutableSpec`: the request (verbatim,
   untrusted), a statement of done, the affected systems, acceptance tests (per system, plus
   whole-system tests that name a check), contracts and budgets. The spec is hashed; "accepted"
   always refers to that hash; the spec's `request` is always the caller's verbatim text.
   With `require_spec_review: true` the job then waits in `awaiting_spec` (audited with the
   spec hash; the A2A task becomes `input-required`) until `PUT /jobs/{id}/spec` (or `a2agw vsc
   spec edit`) confirms or replaces the spec. The spec is refused (failing closed) when it names
   an unknown system or check, repeats an acceptance id, has a per-system acceptance test for a
   system outside the spec, a whole-system test whose check covers none of its systems, or two
   or more systems not covered by whole-system checks.
2. **System map.** Phase 5b. In 5a the affected systems come from the spec, checked against the
   configured systems.
3. **Plan.** The planner writes the plan once: ordered steps, one edit step per system, with
   dependencies, contracts and instructions, plus optional privileged steps (`merge`, `deploy`,
   `migrate`, `send`). The plan's hash covers its structure (ids, systems, kinds,
   dependencies, contracts, merge targets); instructions may be reworded later, the steps never.
   The planner sees acceptance test *names*, never their contents. A plan is refused when an
   edit step depends on a privileged step, a merge targets anything but the system's
   `default_branch` or a `merge_targets` entry, its edited systems are not covered by checks, or
   an acceptance test would never run (its system is not edited, or its check names no edited
   system).
4. **Fail on base.** Before the first worker attempt, every per-system acceptance test runs on
   its system's base in a throwaway checkout and must fail; every whole-system check with
   whole-system acceptance tests runs over the bases with their files written in and must fail.
   A test that passes on base (or whose run is inconclusive: spawn error, timeout, output cap)
   fails the job `verification` before any worker token is spent. A system with nothing that
   could execute (no `gate`, no `tests`, no acceptance test with its own `run`, and no
   whole-system acceptance test of a check that names it, like `sidecar-contract` above) fails
   the job `no checks`. Each result is a `vsc.check` row and part of the receipt (`reproductions`).
5. **Workers.** Edit steps run by dependency layer: steps in one repository one after another
   in plan order, different repositories in parallel. Each attempt resets the workspace to the
   last passed step, launches the step's worker as a stdio process in the workspace and hands it
   the spec, its system, its contracts, the previous failure (if any) and the instructions.
6. **Verifier.** The worker's tree (tracked and untracked files, never ignored ones) becomes a
   candidate commit first; the diff hash and the `touched_tests` flags (changes under `tests/`,
   `test/`, `__tests__/`, to `conftest.py`, `pytest.ini`, `tox.ini`, `noxfile.py`, a
   `pyproject.toml` `[tool.pytest]` section or `package.json` `test*` scripts) come from it.
   Then ranked checks run in a fresh detached checkout of that commit (`clean -fdx`), stopping
   at the first failure: `path_confinement` (no change outside the system's `path`), the
   system's `gate`, each per-system acceptance test (`reproduction_after`, with the test's
   files written into that checkout only), the system's `tests` (`regression`), then `contract`
   (the system's side of each contract that has a test file). A verification that executed no
   check fails (`no checks`). A passed candidate becomes the job branch's head; acceptance
   files never reach a job branch. The next attempt starts from the last passed commit the job
   recorded, whatever the worker did to the branch. When every edit step has passed, every
   check that names an edited system runs over throwaway checkouts of the passed commits (the
   bases for untouched systems) with its acceptance files written in; a failure sends the job
   back to the planner (below). The heads they passed on are recorded per repository.
7. **Gate.** Privileged steps wait in `awaiting_approval` for a human unless `auto_approve`
   allows them. A `merge` step then fast-forwards its `target_branch` in the main repository to
   the verified head, and only while the job branch still points at it (refused otherwise, or
   unless it is a fast-forward of an existing local branch that is the system's
   `default_branch` or listed in `merge_targets`); `deploy`, `migrate` and `send` are approval
   records only in 5a.
8. **Receipt.** When the job is accepted (and on demand for a failed or cancelled job), the
   receipt is built from the job's rows and its audit rows and anchored in the audit chain.

Job states: `submitted` → `planning` → `running` → `verifying` → (`awaiting_approval`) →
`accepted` (with `awaiting_spec` after intake when `require_spec_review` is set), or `failed`
(reason `planner`, `verification`, `no checks`, `whole_system`, `budget` with the limit hit,
`rejected`, `merge_refused`, `resume` or `error`) or `cancelled`. Every attempt is a new step
row; nothing is reused. A restarted gateway resumes every unfinished job: an attempt a dead
process left running is closed as interrupted, half-done worktrees are reset to the last passed
step, approvals already given stay given, and a job whose whole-system checks had passed goes
straight back to the gate. A job that cannot be resumed (its workspace is gone, git fails) fails
`resume`; the other jobs still resume.

## The `deliver` agent over A2A

Jobs are A2A tasks of the `deliver` agent (`/agents/deliver/`), so any A2A client can submit
and approve them:

- **Submit.** Send the request as text, in a context where you have no job. The job starts in
  the background; the task stays `working` and streams `job <id>: <state>` status updates. It
  ends `completed` ("job <id> accepted") or `failed` ("job <id> failed (<reason>)" or
  "cancelled"). If the task's deadline nears first, it completes with "job <id> continues" and
  the job goes on; send any message in the same context to ask for its state.
- **Approve.** When a privileged step waits, the task becomes `input-required` with the
  question "job <id> awaits approval of step <step> (<kind>): reply 'approve [note]' or
  'reject [note]'"; for a merge the question also names the target branch and the verified
  commit it would fast-forward to. Reply in the same context with `approve` or `reject` and an
  optional note; the task then follows the job again. Since the reply comes from the job's
  owner, an A2A approval needs `allow_self_approval` (or the owner listed in `approvers`, or an
  admin principal); otherwise approve through the admin API as another principal. An
  `input-required` task survives a gateway restart.
- **Spec review.** With `require_spec_review`, the task becomes `input-required` after intake
  with the spec hash; confirm or edit the spec with `PUT /a2agw/admin/vsc/jobs/{id}/spec`.
- **Cancel.** Cancelling the task (`tasks/cancel`) cancels the job it follows.
- Jobs are per (context, owner). With `auth` configured the caller needs the `a2agw:vsc`
  scope (`a2agw:admin` implies it).

`vsc-planner` is the planner's own agent: only the gateway itself may call it (see
[Security notes](#security-notes)).

## Admin API

Under `/a2agw/admin/vsc`, with the admin API's rules: the `a2agw:vsc` scope or `a2agw:admin`
(`admin_without_auth: true` on a gateway without auth, for development), and the header
`X-A2AGW-Admin: 1` on every POST and PUT. Errors are `{"error": ...}` with 400 (plus `field`),
404, 409 (plus `state`) or 503. A principal without `a2agw:admin` sees and acts on its own
jobs only (404 for anyone else's).

| Route | |
|---|---|
| `GET /jobs?state=&limit=` | list jobs (own jobs unless admin; `limit` 1-500, default 100) |
| `POST /jobs` `{"request"}` | submit; 201 `{"job_id", "state"}`; the caller owns it |
| `GET /jobs/{id}` | the job, its request, spec, plan, steps, `waiting_step` and `waiting` (the step's kind; for a merge its target branch and the verified commit) |
| `GET /jobs/{id}/receipt` | the receipt (409 until the job has finished) |
| `POST /jobs/{id}/approve` `{"step_id", "note"}` | approve the waiting step (409 unless the job is `awaiting_approval` and `step_id` is the step it waits for; 403 unless the caller may approve: an admin, a listed `approvers` entry, or, with no list, anyone but the owner unless `allow_self_approval`) |
| `POST /jobs/{id}/reject` `{"step_id", "note"}` | reject it; the job fails `rejected` |
| `POST /jobs/{id}/cancel` | cancel; running workers and checks are stopped |
| `PUT /jobs/{id}/spec` | confirm or replace the spec (an `ExecutableSpec`, validated like intake's; its `request` is replaced by the job's verbatim request; 409 outside `awaiting_spec`; audited as `spec_edited`); the job then plans and runs |

## CLI

These call the configured gateway's admin API (`base_url` from `-c a2agw.yaml`) with the key in
`A2AGW_API_KEY` (prefer it to `--api-key`):

```bash
a2agw vsc submit "Rename qty to quantity in the contract"      # prints the job id
a2agw vsc status <job>                                          # state, steps, waiting step
a2agw vsc approve <job> <step> --note "looks right"             # --reject to reject
a2agw vsc spec edit <job> spec.yaml                             # only in awaiting_spec
a2agw vsc receipt export <job> receipt.json                     # mode 0600
a2agw vsc receipt verify receipt.json                           # offline; exit 1 with the problems
```

The `bench` commands run locally, without a gateway: see [The benchmark](#the-benchmark).

## Workers

A worker is an external coding agent the runner launches for one step attempt: a `StdioAdapter`
on the worker's `command`, with its working directory at the workspace root, speaking the
invoke protocol `a2agw.invoke/1` over JSON lines exactly as a stdio sidecar agent does
([docs/sidecar.md, Stdio transport](sidecar.md#stdio-transport)). The runner sends one `invoke`
per attempt (its text is the step prompt: the statement of done, the request, the system and
step, the confinement rule, the contracts, the previous failure with a stderr tail, then the
instructions) and reads events until `done` or `failed`. A `usage` event is charged to the
budget. The worker also gets a consult grant, so it can ask partner agents through the gateway.
Its environment is `PATH`, `HOME`, `LANG`, `TZ` and `PYTHONPATH` from the gateway's, plus the
worker's `env`; credentials belong in `env` through `${VAR}` substitution, never in the file.

Workers are not hosted agents and are never imported: any program that speaks the protocol is
one. Claude Code, Codex CLI and OpenHands do not speak `a2agw.invoke/1` themselves, so each runs
behind a small bridge: a stdio program that reads `invoke` lines, runs the agent's
non-interactive mode in its working directory with the invoke `text` as the prompt, and answers
with a `usage` event (when the agent reports one) and `done` (or `failed`). 5a ships no bridges;
the agents' non-interactive modes at the time of writing (check your versions):

| Agent | Non-interactive mode | Usage |
|---|---|---|
| Claude Code | `claude -p <prompt> --output-format json` | the JSON result carries token usage and cost |
| Codex CLI | `codex exec <prompt>` (`--json` for events) | from its JSON events |
| OpenHands | its headless CLI or the OpenHands SDK in the bridge process | from the SDK's metrics |

Register a bridge as a worker with `cost_class` set to how strong it is: the retry policy
escalates from cheaper to stronger. A worker that reports no usage sets `reports_usage: false`;
it then runs under the time and attempt caps only, and the receipt marks its usage
`usage_reported: false`.

The fake worker `tests/vsc/worker_agent.py` (modes `apply`, `patch`, `fail`, `hang`, ...) is
for tests only: it writes whatever files or patch its instructions carry.

## Budgets and the retry policy

A job's limits are the tighter of `vsc.budgets` and the spec's own (a request can never raise
its own budget):

- **Tokens and cost** are charged after every worker and planner turn; exceeding one fails the
  job `budget` (`limit: tokens` or `cost`).
- **Attempts** are per step, counted from the step's stored rows, so the bound holds across
  whole-system rounds and restarts. An interrupted attempt (cancel, deadline, a failing
  sibling, a restart) does not count; interrupted attempts are capped apart at twice the
  budget (`budget`, `limit: interrupted`).
- **Deadline** bounds active time (planning, running, verifying); time waiting for an approval
  never counts. Every check's timeout is cut to the time left.

After a failed attempt the planner decides: `retry` (same worker, with the failure), `escalate`
(the first configured worker of a stronger cost class), `replan` (new instructions, same steps:
a changed plan structure becomes `stop`) or `stop` (the job fails `verification`). Without a
decision to escalate, the second failure of a step escalates anyway (`escalate_after`: 2). A
whole-system check that fails returns the job to the planner with the failure and re-runs the
edit steps of that check's systems, at most `attempts` rounds, then the job fails
`whole_system`. Every attempt is recorded with its cost.

## The gate and `auto_approve`

Plan steps of kind `merge`, `deploy`, `migrate` or `send` are privileged: the job moves to
`awaiting_approval` and waits for `approve` or `reject` (A2A reply, admin route or CLI). Every
decision is an audit row (`vsc.approve`, with the principal and the note), so a resumed job
finds an earlier approval instead of asking again; the most recent decision wins. A rejection
fails the job `rejected`.

Who may approve: an admin (`a2agw:admin`) always; otherwise a principal listed in
`vsc.approvers` when the list is set, or anyone but the job's owner when it is empty (the owner
too with `allow_self_approval: true`). Anyone who may see the job may reject it.

`auto_approve` lists `{system, action}` pairs that pass without a human; a merge rule names
the one target branch it covers:

```yaml
vsc:
  auto_approve:
    - {system: core, action: merge, target_branch: main}  # fast-forward main unattended
```

An automatic approval is a `vsc.approve` audit row with actor `policy` and outcome `auto`, and
the receipt lists it. Nothing a worker, a repository
or a request says can approve a step: only a principal with the scope, or this policy.

## Receipts

`GET /a2agw/admin/vsc/jobs/{id}/receipt` (or `a2agw vsc receipt export <job> <file>`) returns
the job's receipt, `a2agw.receipt/1`: the spec and its hash, the plan and its hash, the
`deliver` task ids that drove the job, the planner's turns (task id and usage each), each
repository's base and verified head, every step attempt (worker, usage, whether usage was
reported, every check with its command, exit status, duration and log hash, the diff's sha256,
the base and the commit, `touched_tests`; for a merge its target, verified head and result),
the fail-on-base reproductions and the whole-system checks (command, exit code, log hash, the
heads they ran on), every approval with its principal (policy approvals included), the job's
totals (tokens, cost, attempts, active time) and the
slice of the audit chain from the job's first row to its last. Diffs and logs are never stored,
only their hashes; check stderr tails are redacted. The receipt is built once and returned unchanged on
later calls; a `vsc.receipt` audit row carries its hash.

`a2agw vsc receipt verify <file>` needs nothing but the file. What it proves, in the receipt
module's own words:

> What offline verification proves: the bundle is internally consistent (hashes, chain links)
> and the job's own rows are complete relative to what the receipt claims (every cited and
> listed seq is present as a full row of this job, none is a stub, no further row of this job
> hides in the span). It does not prove the bundle is the gateway's: a forger who rewrites the
> claims and recomputes every hash is caught only by comparing `receipt_hash` with the
> gateway's `vsc.receipt` row.

Only the job's own audit rows are embedded in full; another job's row inside the span is an
opaque stub (`seq`, `prev_hash`, `hash`) that keeps the chain linkable without disclosing it.

## The benchmark

`a2agw.vsc.bench` measures VSC against a single agent at a matched token budget. Two corpora:
the demo estate's ten scenarios (`--corpus estate`) and tasks mined from a repository's history.

```bash
uv run a2agw vsc bench mine . --out bench-tasks -c a2agw.yaml   # commits changing 2+ systems that add tests
uv run a2agw vsc bench run --corpus estate --mode oracle --out bench-out    # validate the corpus
uv run a2agw vsc bench run --corpus estate --mode vsc --out bench-out -c my-a2agw.yaml
uv run a2agw vsc bench run --corpus estate --mode single --out bench-out -c my-a2agw.yaml
uv run a2agw vsc bench report bench-out                        # bench-out/report.md
```

- **Mining** keeps a first-parent commit only if it touches at least `--min-systems` declared
  systems and adds tests that fail on its parent and pass at the commit. The task's repository
  is rebuilt from the base commit alone, so the solution is not reachable from a workspace.
- **Modes.** `vsc`: a job runner per task with the configured planner and workers. `single`:
  the first configured worker in one workspace holding every repository of the task, given the
  request, up to `attempts` turns, verified with the same checks. `oracle`: applies the task's
  reference patch (validates the corpus; no model).
- **Method overrides**, identical for every task (printed at the top of every report): both
  modes are told the affected-repository set; in `vsc` mode privileged steps are removed from
  the plan and the task's acceptance tests and budget replace those intake produced (the planner
  sees the tests' names, never their contents); `single` is unconfined in its one workspace;
  `single`'s token budget is the `vsc` run's recorded tokens (planner and workers) for the task,
  so run `vsc` first.
- **Failure classes**: `timeout`, `budget`, `worker_error`, `missed_system` (the failing check
  needed a repository left unchanged), `wrong_behaviour`. The report gives, per mode, tasks,
  solve rate, mean tokens, cost and wall time, the failure breakdown, and the matched-budget
  line over the tasks where `single`'s budget equalled `vsc`'s recorded tokens.

`vsc` and `single` call real models and cost money; they run manually, never in the test gate.

## The injection suite

`tests/vsc/test_injection.py` runs thirteen cases (`tests/vsc/injection/*.yaml`) in which the
request, a repository file or the worker's output carries instructions aimed at the agents
(push to origin, skip approval, add a deploy step, read `~/.ssh`, mark the check as passed), or
the worker itself acts on one (writes outside its path, runs `git push`, copies a secret into
its workspace). With the scripted planner it proves that the runner, verifier and gate never act
on text (the receipt's plan hash is the planner's plan, no step outside it ran, no privileged
step executed without approval, a wrong change stays failed, the receipt verifies), that worker
and repository text never reaches an audit row's detail and a canary private key never reaches
the audit log or the receipt, and that a write outside the system's path fails the step. It does
not test a model planner's judgement or OS-level sandboxing; the push and secret-copy cases are
recorded as known gaps (below), not hidden.

## Security notes

- **Plan-then-execute.** The plan is fixed before any worker runs, and its structural hash is
  checked on every replan: worker output, repository content and partner replies can change a
  step's instructions, never add a step, a system or a privileged action.
- **The planner sees no hidden tests.** It gets acceptance test ids and file names only; the
  contents are for verification.
- **Untrusted text.** The request and everything from repositories, workers and logs is
  untrusted; the planner's prompts say so and fence the request as a JSON string. Worker
  output is capped at 64 KiB.
- **Allowlisted environments.** Checks get only `PATH`, `HOME`, `USER`, `SHELL`, `LANG`,
  `TERM`, `TMPDIR`, `TZ`, `VIRTUAL_ENV`, `CI` and variables starting `LC_`, `PYTHON`, `UV_`,
  `NODE_`, `npm_config_`, `GIT_` (plus `VSC_WS_*` for whole-system checks); workers get `PATH`,
  `HOME`, `LANG`, `TZ`, `PYTHONPATH` and their own `env`. Never the gateway's whole environment.
- **Redaction.** Check output is hashed, not kept; the 2 KiB stderr tail in a check result has
  secret-named variables' values and common token shapes (bearer tokens, API keys, JWTs,
  private keys, URL passwords) masked. It is a best-effort second layer: keep secrets out of
  test output.
- **Internal planner key.** `vsc-planner` admits only the holder of an API key the gateway
  mints when VSC is attached and holds only in memory, with or without `auth`
  (`AgentAccess.api_key_sha256`); with `auth` the key is also the principal `key:vsc-internal`,
  the only one the agent admits. Jobs cannot be driven by calling the planner directly.
- **A planner without tools.** The claude planner runs with every Claude Code built-in tool
  disabled (`tools=[]` plus all of them in `disallowed_tools`), no MCP server
  (`strict_mcp_config`), no settings, skills or plugins (`setting_sources=[]`), at most four
  turns, in a private empty temporary directory (mode 0700), never the gateway's directory.
  Its replies are cut to 256 KiB before parsing.
- **Verification outside the worker's tree.** Checks run in detached throwaway checkouts of the
  candidate commit cleaned with `clean -fdx`, so ignored files a worker leaves behind never
  reach them, and the acceptance files are never written into a workspace or committed.
- **Git hygiene.** Every git process the gateway starts gets the allowlisted environment (minus
  `GIT_DIR`, `GIT_WORK_TREE`, `GIT_INDEX_FILE`), runs with `core.hooksPath=/dev/null` (no
  repository hook runs), commits with `--no-verify` and `commit.gpgsign=false`, and is killed
  with its process group when the job is cancelled.
- **Owner scoping.** `a2agw:vsc` holders see, approve and cancel their own jobs only;
  `a2agw:admin` sees all. Every write needs `X-A2AGW-Admin: 1` (CSRF).
- **Workspaces hold no credentials** of the gateway's, and nothing is pushed: the only write
  outside a workspace is the local fast-forward of an approved `merge` step.

## Known limitations

Phase 5a, local and single-process by design:

- **Local repositories only.** `repo` must be a local path (clone URLs are refused), and
  results are local branches: nothing is pushed and no pull request is opened (forge clients
  and credentials are Phase 5b).
- **No OS sandbox.** Workers run as ordinary processes with the gateway user's rights.
  Confinement is by instruction and by the `path_confinement` check on the diff, so a worker can
  still run `git push` from its workspace or copy a file it can read into the workspace and pass
  verification (the injection suite's `action-push` and `action-exfil` cases). Sandboxes with an
  egress allowlist are Phase 5c.
- **Test edits are flagged, not refused.** A change to tests or test configuration is listed in
  `touched_tests` in the step result and the receipt for a reviewer; it does not fail the step.
- **Contract checks are thin.** A contract without a test file passes as "no contract test",
  and a system's regression run can pass by skipping tests; only whole-system checks that
  enforce zero skips (the estate's) catch that.
- **The whole-system check runs from the first listed system's workspace**, so list the
  system whose suite drives the others first.
- **Retry policy, partial.** No best-of-N sampling after the third failure, no automatic
  substitution of an unavailable worker, and no option to refuse workers that report no usage.
- **The LLM reviewer is not produced.** The `review` check kind exists; advisory review lands
  with the Console (5c).
- **Single process.** One gateway process runs a job (SQLite or PostgreSQL store); distributed
  workers (DBOS or Temporal) are Phase 5c.
- **No system map.** Affected systems come from the spec; indexers and the map are Phase 5b.
- **No worker bridges ship.** Claude Code, Codex CLI and OpenHands need a bridge program (see
  [Workers](#workers)); the gate's tests use a fake worker.
- **Not wired into the control plane yet.** Jobs and receipts are reachable through the VSC
  admin routes and the `deliver` agent; the Phase 4a control-plane views and the VSC metrics
  (jobs by state, acceptance rate, cost per accepted change, wall time) follow when 4a lands.
- **Live numbers pending.** The estate end to end with the real planner and the matched-budget
  benchmark with real models have not been run for this release; their tokens, cost and wall
  time will be recorded here and in `docs/vsc-benchmark.md`.
