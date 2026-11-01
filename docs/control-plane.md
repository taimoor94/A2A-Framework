# Control plane

The control plane (`a2agw.control`, the `control` extra) owns the partner catalogue, the
policies, the users and roles of the Console, and the list of gateways. Gateways connect out
to it; it never calls a gateway.

This document is filled in as Phase 4a lands. The sections on deployment and roles follow
with the tasks that build them; the Console's read API is under [Console read API](#console-read-api).

## Gateways

### Enrolling a gateway

1. Register the gateway on the control plane: `POST /api/v1/gateways {"name": "eu-1"}`
   (permission `gateways.manage`) answers `{id, name, token}`. The token is shown only in
   that response; the control plane keeps its SHA-256 digest.
2. Give the token to the gateway in an environment variable (never in the config file), and
   add a `control_plane` section to its `a2agw.yaml`:

```yaml
control_plane:
  url: https://cp.example.com     # https (plain http only with A2AGW_DEV=1)
  token_env: A2AGW_CP_TOKEN       # required: the variable holding the gateway token
  tls_ref: null                   # optional: an entry of the tls section (mTLS to the CP)
  manage: [partners, policy]      # the sections the control plane owns (default: both)
  report_interval_s: 1.0          # how often reports are posted
  health_interval_s: 15           # how often health, metrics and gateway info are sent
```

3. Start the gateway (`a2agw serve`). It connects, receives its desired state (the partners
   and the policy assigned to it) and reports what it applied.

A managed section cannot also be configured locally: `policy_file` with
`manage: [policy]`, or a `partners:` list with `manage: [partners]`, is a configuration
error. A gateway that manages its partners has no partners file (`partners_file` and the
`a2agw partners` commands do not apply to it). `classifier` works with a managed policy too.
Without a `control_plane` section the gateway behaves exactly as before.

Rotating the token (`POST /api/v1/gateways/{id}/tokens`) or revoking the gateway
(`POST /api/v1/gateways/{id}/revoke`) closes its open stream at the next poll. A gateway
whose token is refused (401) stops its connector: it logs one error naming `token_env`
(never the token) and `/a2agw/admin/healthz` shows `last_error_kind: "unauthorized"`.
Restart it with the new token.

### The connection

The gateway's connector (`a2agw.ops.cp_client.ControlPlaneConnector`) holds one
server-sent-events stream, `GET {url}/cp/v1/stream?applied=<version>&epoch=<epoch>`, and
posts reports to `{url}/cp/v1/report` on separate requests. Both carry the token in the
`Authorization: Bearer` header only; it is read from `token_env` at each connection and
never logged or put in a URL. Connections go through the gateway's guarded HTTP client at
the `internal` tier (with `tls_ref`, presenting that client certificate).

A lost connection is retried with jittered exponential back-off: 0.5 s, doubling up to
30 s, each delay drawn from the upper half of its range; a successful connection starts the
sequence over. Connecting and disconnecting are audited as `cp.connect` (coalesced: at most
one row per outcome per minute, with `detail.count`).

### Desired state

The stream sends the gateway's desired state whenever it differs from what the gateway
reported having: `{epoch, version, hash, partners, policy}`. The gateway applies it under a
lock, partners first, then the policy, and only if every local check passes:

- the document's `hash` matches its content;
- each partner record carries only the catalogue's fields (`id, card, card_hash, tier,
  credential_ref, tls_ref, tags, card_url`: status, pending cards and verified key ids are
  the gateway's own), validates as a partner record, has `card_hash` equal to the hash of
  `card`, names a `tls_ref` the gateway has, and passes the gateway's own checks: the SSRF
  check of every interface URL for its tier, and signature verification for the tiers in
  `trust.require_signed`;
- the policy validates (`Policy.model_validate`, through `parse_policy`).

If anything fails, nothing from that state is applied: the previous partners and policy stay
in force. The gateway reports `applied: {status: "rejected", reason}` (the reason is the
dotted path of the offending fields, such as `partners.0.card_hash` or
`policy.authz.0.principal`, or the partner and the failed check's error class, such as
`acme: UnsafeURL` or `acme: CardSignatureError`; never a value, URL or message) and audits `cp.reject`. The control plane shows it as
the gateway's last rejection.

An applied state is saved in the gateway's database (`a2agw_cp_state`, key
`applied_state`), audited as `cp.apply` (`detail.version`, `detail.hash`), and reported
(`applied: {status: "applied"}`).

The control plane decides the catalogue; it cannot switch off the gateway's local defences.
A partner whose card is the one the gateway already has keeps its local state: a card change
the gateway's own refresh found stays quarantined until it is approved (a new approved card
from the control plane, or a `partner.approve` command). A new card from the control plane
replaces the record. A partner left out of the desired state is removed, unless it still has
open partner tasks: then it is disabled at once (no new consult starts) and removed by the
gateway's maintenance pass once those tasks have ended.

A managed policy of `null` (the control plane assigns no policy to the gateway) does not
open it: the gateway is locked down exactly as on a first start (the lone deny
`cp:unconfigured`, audited as `policy.update`), and `/a2agw/admin/healthz` says no policy is
assigned. Assigning a policy lifts the lockdown.

**Versions and epochs.** Versions grow within the control plane's store epoch. A state of the
epoch already applied with a version that is not higher than the applied one is ignored. A
state of another epoch (the control plane's database was reset or replaced) is applied
whatever its version, so a reset never strands a gateway on an old version.

### Fail static

The gateway keeps serving what it has whenever the control plane is unreachable: a lost
connection changes nothing in force.

- At startup, before it serves, a gateway with managed sections loads `applied_state` from
  its database and puts it in force again (local checks only: no network is needed). A
  gateway restarted while the control plane is down serves its last applied partners and
  policy.
- With no cached state and no control plane (the very first start), managed partners are
  empty and a managed policy is a lockdown: a lone deny rule with id `cp:unconfigured`,
  which denies every call to every agent (audited as `policy.update`). The log and
  `/a2agw/admin/healthz` (`control_plane.warning`) say the gateway is waiting for its first
  desired state. The first state it applies lifts the lockdown.

### Commands

The stream also carries commands queued by operators (`command` frames with `id`, `kind`,
`args`, `expires_at` and `actor`). Each runs the gateway's shared write operation
(`a2agw.ops.actions`), audited on the gateway as actor `cp:<actor>`, and its result is
reported: `done` with the operation's result, or `failed` with `{"error": ...}` (`not_found`,
`conflict`, `refused`, `invalid_args`, `unknown_command`, `card`, `internal`; refusals add
a `detail` with ids and reasons only).

| Kind | Args | Operation |
|---|---|---|
| `task.cancel` | `agent_id, task_id` | cancel a task (and the partner tasks it started) |
| `task.answer` | `agent_id, task_id, text` | answer an `input-required` task for its owner |
| `task.get` | `agent_id, task_id` | the task's compact detail (see below) |
| `partner.refresh` | `id` | re-fetch the partner's card now |
| `partner.approve` | `id, expected_hash` | approve a quarantined card change with that hash |
| `partner.reject` | `id` | refuse a quarantined card change (the partner is disabled) |
| `tasks.reap` | `agent_id, confirm?, force?` | fail the open tasks of an agent nobody serves |

A result is at most 8 KiB as JSON, 64 KiB for `task.get`; a larger one is reported (and
kept) as `{"truncated": true}`, the last resort. `task.get` answers a compact detail sized
to fit: the task's id, context, state, owner, timestamps and trace; its last 10 messages
with at most 4 parts each, every text part clipped to 1 KiB (UTF-8) and other parts as
metadata only (`kind`, `name`, `media_type`, `size`); its last 20 artifacts as metadata
only; its last 20 partner tasks; `history_total`, `artifacts_total`, `partner_tasks_total`;
and `clipped: true` when anything was cut. The gateway's own admin API keeps the full
detail.

Commands are delivered at most once. One whose `expires_at` has passed when it arrives
(measured in control-plane time, from the stream's `hello`) is not run: it is reported
`failed` with `{"error": "expired"}`. A result that arrives after the command expired on the
control plane is ignored there (counted in the report's `dropped`).

### Reports

Every `report_interval_s` the gateway posts what it has to say, in one report:

- up to 500 bus events (`task.state`, `partner.call`, `partner.state`, `security.denied`),
  from a queue of 10 000 (a full queue drops its oldest events, counted in
  `status.dropped`);
- the audit rows after `audit_acked_seq`, ascending, up to 500. `audit_acked_seq` (kept in
  `a2agw_cp_state`) moves only to the response's `acked_audit_seq`, so rows not acknowledged
  are sent again; the control plane stores them once;
- command results (at most 8 `task.get` results per report, the rest in the next ones), and
  the outcome of each state applied or rejected;
- every `health_interval_s`: health, the metrics snapshot (`/a2agw/admin/metrics`) and the
  gateway info `{version, agents, base_url}`. Each agent is `{id, name, version, skills,
  card_url}` from the hosted agent's spec (the source of its card): at most 200 agents and
  64 skill ids each, strings cut to 256 characters. The control plane also accepts the
  older form, a list of agent ids, and stores it with the other fields null.

`partner.call` events carry the `trace_id` of the turn that made the call (null outside a
span), as `task.state` events do.

A report that fails is sent again, whole; after a `413` the gateway sends smaller reports
until one fits. At shutdown the gateway waits for running commands, then posts one last
report (2 s at most, within the connector's 5 s shutdown bound), so the latest events and
results are not lost.

### Status

`/a2agw/admin/healthz` has a `control_plane` object: `connected`, `applied_version`,
`last_error_kind` (`unauthorized`, `no_token`, `http_<status>`, `stream_ended` or an error
class), `queue` (events not yet reported), `dropped`, and `warning` while the gateway waits
for its first state or is locked down because no policy is assigned.

### Limits

- One gateway per database: `a2agw_cp_state` holds one gateway's state.
- Applied and rejected outcomes are reported one per report, so after a burst of states the
  control plane learns the last one a few report intervals later.
- A report carrying a `task.get` result can be up to 64 KiB larger than one without. Keep
  the control plane's `limits.report_max_bytes` (1 MiB by default) well above that: after a
  `413` the gateway halves its report down to a single event and result, which must still
  fit.

## Partner catalogue

The catalogue is the central registry: each partner is registered once and assigned to the
gateways that use it. A partner's status is `pending` (nothing approved yet), `approved`,
`quarantined` or `rejected`; only an approved partner is sent to its gateways, as its
approved card version. Every write is audited in `cp_audit`.

| Route | Permission | What it does |
|---|---|---|
| `POST /api/v1/partners` `{id, card_url \| card, tier, credential_ref?, tls_ref?, tags?}` | `partners.register` | fetch the card (SSRF-guarded for the tier), validate and verify it; version 1, `pending` |
| `GET /api/v1/partners?tier=&status=&gateway_id=&q=` | `read` | the list; `q` is the skill search. Without `status` only `approved` partners are listed and searched |
| `GET /api/v1/partners/{id}` | `read` | approved card, pending card, their `diff`, the versions, what each gateway reported |
| `POST /api/v1/partners/{id}/approve` `{version, expected_hash}` | `partners.trust` | approve that version (409 if the hash differs; the card is checked again for the current tier, 422 `card` if it fails) |
| `POST /api/v1/partners/{id}/reject`, `.../quarantine` | `partners.trust` | the partner leaves every gateway |
| `POST /api/v1/partners/{id}/refresh` | `partners.register` | fetch the card again |
| `PUT /api/v1/partners/{id}/settings` `{tier?, credential_ref?, tls_ref?, tags?}` | `partners.trust` | change the operator's fields (`null` clears a ref) |
| `PUT /api/v1/gateways/{gid}/partners` `{partner_ids}` | `assign` | replace the gateway's partners |

- **Cards.** The control plane fetches and checks cards with the gateway's own code: no
  redirects, a 1 MiB cap, the tier's address rules (a `public` partner on a private address
  is refused), interface URLs checked for the tier, and a signature check for the tiers in
  `trust.require_signed` (the keys of `trust`, files relative to control.yaml). A card that
  fails is a 422 `{"error": "card", "detail": "<class>"}`: `UnsafeCardURL`,
  `CardUnavailable`, `InvalidCard`, `CardSignatureInvalid` or `UnsafeInterfaceURL`. A card
  given inline is checked the same way and cannot be refreshed.
- **Refresh.** A significant change (anything but `version`, `documentationUrl`, `iconUrl`,
  `provider` and the signatures, or a new signing key) is stored as a pending version: the
  partner stays approved with `pending: true` and its gateways keep the approved card until
  the new version is approved. A cosmetic change of an approved partner is applied at once
  as a new approved version.
- **Settings.** A tier change is a trust change (audited with `reason: trust`): the approved
  and pending cards are checked again for the new tier first.
- **Gateway reports.** Each gateway's `partner.state` events are kept per gateway: the list
  shows `quarantined_on`, the detail each gateway's status and the hash of the pending card
  it holds. Only that hash is taken from a gateway, never a card, and a report never makes
  the control plane fetch anything: to see the diff of a gateway-reported quarantine, run
  `refresh` on the partner (the control plane fetches the card itself and stores the change
  as a pending version). Approving the version with that hash also queues
  `partner.approve {id, expected_hash}` for those gateways.
- **References only.** `credential_ref` and `tls_ref` are names each gateway resolves from
  its own configuration. The control plane holds no partner secret, and it fetches cards
  without a client certificate: register an mTLS-only partner with its card inline.

## Policies

A policy is a named series of versions. Each version is a policy document (the same
schema as a gateway's `policy_file`, see the policy reference), validated when it is
saved and stored normalized, with every default filled in, and with its hash: the
`policy_hash` the gateway audits as `policy.update` when it applies the version. Versions
are never edited. To change a policy, save a new version. Every write is audited in
`cp_audit` (`cp.policy.save`, `cp.assign`, `cp.policy.dryrun`) with ids, version numbers
and hashes only, never a document.

| Route | Permission | What it does |
|---|---|---|
| `POST /api/v1/policies` `{name, doc, comment?}` | `policy.edit` | create the policy at version 1 |
| `POST /api/v1/policies/{id}/versions` `{doc, comment?}` | `policy.edit` | save the next version |
| `GET /api/v1/policies` | `read` | each policy with version summaries and the gateways it is assigned to |
| `GET /api/v1/policies/{id}` | `read` | every version with its document and a unified `diff` from the version before (over canonical YAML) |
| `PUT /api/v1/gateways/{gid}/policy` `{policy_id, version}` | `assign` | the gateway's one policy: a version number pins it, `null` follows the latest version |
| `POST /api/v1/policies/dry-run` `{doc, gateway_ids?, days = 7}` | `policy.edit` | replay recent gateway audit rows against a candidate document |

- **Validation.** A document that fails validation is a 422 whose `fields` are dotted
  paths under `body.doc` (`body.doc.authz.0.principal`). Values are never echoed.
- **Warnings.** Create and version responses carry `warnings`. A deny rule with no allow
  rule is reported as `lone deny rule locks down every agent`, because a lone deny is a
  lockdown and not a blocklist. A deny rule for an agent that no allow rule names, and a
  routing rule that names a partner the catalogue does not know, are reported too. These
  are warnings only: the version is saved.
- **Assignment and desired state.** The assigned version (the pinned one, or the latest)
  is the `policy` of the gateway's desired state. A new version marks every gateway that
  follows the latest version, so they get it at their next poll. Pinned gateways keep
  their version. **A gateway with no policy assigned is locked down.** Its desired state
  has `policy: null`, and a gateway with `manage: [policy]` treats that as the lone deny
  `cp:unconfigured`, so every call to every agent is denied until a policy is assigned.
- **Dry-run.** Replays the gateways' audit rows (all gateways, or `gateway_ids`) of the
  last `days` (1 to 30), newest first, against the candidate. At most 50 000 rows are
  read. When more rows match, `truncated` is true. The rows are read in batches and
  evaluated off the request loop.
  - `inbound.admit` rows, and `authz.deny` / `inbound.reject` rows that were the policy's
    own refusal, go through `authorize(principal, agent, None)`. AgentAccess refusals are
    not the policy's decision and are skipped.
  - `partner.call` and `egress.deny` rows go through the routing `forbid` rules (with the
    partner's tags and approved card from the catalogue) and then the tier and partner
    ceilings. The level used is the row's `classification`, raised to the candidate's
    agent default. A partner call the gateway refused because of a routing forbid is
    recorded as `partner.call` with outcome `unavailable` and detail `reason:
    routing.forbid`, plus the forbidding `rule` and the caller's label. The dry-run
    counts it as blocked then, so a candidate that lifts the forbid lists it in
    `newly_allowed` when the ceiling lets it through.
  - The response shape is:

    ```
    {"evaluated": int,
     "newly_blocked": [{gateway_id, seq, ts, actor_kind, agent_id, partner_id, action, rule}],
     "newly_allowed": [... same entries ...],
     "truncated": bool,
     "not_replayable": ["egress content checks"],
     "counts": {"newly_blocked": int, "newly_allowed": int, "skipped": int}}
    ```

    `evaluated` counts the rows replayed, and `counts.skipped` the rows read but not
    replayable. Together they are at most 50 000. Each list holds at most 1 000 entries,
    newest first, and `counts` has the full totals. `rule` is the candidate's deciding
    rule, or its reason when no rule decided (`no matching allow rule`). The caller
    appears only as its kind (`api_key`, `jwt`, `anonymous`, `system`), never by id.
  - A row is skipped, never guessed, when it lacks what replay needs. Skipped rows are:
    - a partner call without a `classification`, unless a forbid rule now blocks it or
      the row is a recorded routing forbid;
    - an `unavailable` partner call without a classification and without a `reason`
      (written by gateways before the reason was recorded): it may have been a forbid,
      a circuit or anything else;
    - a recorded forbid whose label did not parse (`detail.classification: invalid`);
    - a call whose tier is unknown;
    - a partner unknown to the catalogue under a forbid rule that matches on tags or
      skills.
  - `not_replayable` lists the checks a replay cannot repeat. `egress content checks`
    is one of them, because the classifier saw message content that audit rows never
    hold. A row's `classification` is the level the gateway computed at the time, so a
    candidate that lowers an agent's default cannot lower the level replayed.

## Console read API

Read views are computed on query from what gateways report (events, audit rows, health,
info) and the catalogue; no materialized tables (the 7-day event retention bounds every
scan). Every list answers `{items, next_cursor}` with `limit` 1..200 (default 50). A cursor
is an opaque keyset position bound to its view and filters: a cursor used with other
filters, or on another list, is a `400 bad_request`, so it never widens what a caller sees.

| Route | Permission | What |
|---|---|---|
| `GET /api/v1/overview` | `read` | gateways, tasks per minute, error rate, top partners, alerts |
| `GET /api/v1/agents?kind=hosted\|partner` | `read` | hosted agents (from gateway info) and catalogue partners |
| `GET /api/v1/tasks` | `read` | the latest state of each task; filters `gateway_id, agent_id, state, since, trace_id, q` (task id prefix) |
| `GET /api/v1/tasks/{gateway}/{agent}/{task}` | `read` | the gateway's compact detail (a `task.get` command, waited for 5 s) plus `timeline`; 202 `{command_id, timeline}` when it does not answer in time. Concurrent requests for one task share one command, an answer is reused for 5 s, and at most 16 requests per process wait at once (the others answer 202 at once); every reader is audited (`cp.command` `queued` or `shared`) |
| `GET /api/v1/topology?window_m=5..1440` | `read` | who called whom, with latency, errors and the policy overlay |
| `GET /api/v1/audit`, `/audit/export?format=jsonl\|csv`, `/audit/verify` | `audit.read` | both audit sources; streamed export; the control plane's own chain |
| `GET /api/v1/credentials` | `read` | credential and TLS reference names |
| `GET /api/v1/users`, `PATCH /api/v1/users/{id}` | `users.manage` | users; `{disabled}` ends the user's sessions at once |
| `GET`/`POST /api/v1/api-keys`, `POST /api/v1/api-keys/{id}/revoke` | `apikeys.manage` | API keys |
| `GET /api/v1/settings` | `settings.manage` | effective settings, without secrets (read-only) |

### Definitions

- **Gateways**: `total` counts active gateways; `connected` means seen within two keepalive
  intervals; `stale` is the rest.
- **Tasks per minute**: the last 60 one-minute buckets (aligned to the minute, the last one
  the current minute), each counting the distinct tasks with a `TASK_STATE_SUBMITTED`
  event in it (new tasks).
- **Error rate**: over the last 15 minutes, failed and rejected tasks among the tasks that
  ended (completed, failed, rejected, canceled); 0 when none ended.
- **Top partners**: the 10 most-called partners of the last hour, with errors (`failed`,
  `unavailable`, `rejected` calls, as the gateway's metrics count them) and the
  nearest-rank p95 of call durations.
- **Alerts**: a gateway not seen for more than 60 s; a partner whose breaker a gateway
  reports open; a partner a gateway reports quarantined; a desired state a gateway rejected,
  until it applies that version or a later one.
- **Topology**: one edge per (gateway, hosted agent, partner) from `partner.call` events in
  the window, with calls, errors and nearest-rank p50/p95 (the 500 busiest edges). Its
  policy overlay (`allowed`, `forbidden`, `forced`, `preferred`) is the gateway's routing
  evaluation under its *stored* desired policy, so it lags an assignment change until the
  desired state is recomputed (the gateway's next stream poll or the maintenance pass, at
  most a minute). A gateway with no policy has no routing rule: every edge is allowed.
- **Task timeline**: every stored event of the task, and every `task.state` and
  `partner.call` event on any gateway sharing one of its traces, oldest first (500 at most).

### Who sees what

- No read view shows a principal id: a task's owner is shown as its kind (`owner_kind`),
  so is whoever answered a prompt (`answered_by_kind`: `console` for an operator here),
  and partner tasks drop their caller. The audit views (`audit.read`) show actors.
- An export is audited (`cp.audit.export`, with its format, source and the names of the
  filters used), streams up to 100 000 rows, and prefixes every CSV cell that starts with
  `=`, `+`, `-`, `@`, a tab or a carriage return with `'` (formula injection).
- An API key is shown once, in the response that creates it. Its role must not carry a
  permission its creator lacks: nobody makes a key above their own permissions.
- Settings drop every `*_env` name and mask the password in `db_url`.
- Task detail results, which hold message text, are kept in `cp_commands` until the
  maintenance purge removes finished commands (`retention.commands_days`, 7 by default);
  a command never answered expires after its TTL (60 s) and is purged the same way.

### Known gaps

- **Audit chain breaks**: no gateway reports a chain check yet, so there is no alert for a
  broken gateway chain. Verify a gateway's chain on the gateway (`a2agw audit verify`).
- **Credential references** come from the catalogue only: gateways do not report the
  credential or TLS reference names they hold.
- Partner calls reported by gateways older than the `trace_id` field join a task's timeline
  only through the partner tasks in its detail.
