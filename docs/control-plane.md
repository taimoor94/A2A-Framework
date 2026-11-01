# Control plane

The control plane (`a2agw.control`, the `control` extra) owns the partner catalogue, the
policies, the users and roles of the Console, and the list of gateways. Gateways connect out
to it; it never calls a gateway. Each gateway keeps enforcing everything locally (SSRF
checks, card signatures, the policy, its own audit chain): the control plane decides what a
gateway runs, never how safely it runs it.

- [Deployment](#deployment): install, `control.yaml`, sign-in, API keys.
- [Roles and permissions](#roles-and-permissions).
- [API overview](#api-overview): every route and the permission it needs.
- [Managed and local mode](#managed-and-local-mode).
- [Gateways](#gateways): enrollment, the connection, desired state, fail static, commands,
  reports.
- [Partner catalogue](#partner-catalogue), [Policies](#policies),
  [Operator actions](#operator-actions), [Console read API](#console-read-api).
- [Retention](#retention), [Running several replicas](#running-several-replicas),
  [Known limitations](#known-limitations).

[`examples/control_plane`](../examples/control_plane/README.md) walks through one control
plane and two gateways with `curl`; `tests/integration/test_phase4a_control_plane.py` runs
the same story as a test.

## Deployment

```bash
pip install 'a2a-gateway[control]'       # FastAPI; add [postgres] for PostgreSQL
a2agw control init                       # writes a commented control.yaml
a2agw control serve -c control.yaml --host 0.0.0.0 --port 8100
```

`serve` checks the database before the server starts. Put TLS in front of it (a reverse
proxy or a load balancer) and set `base_url` to the https URL people and gateways use:
gateways refuse a plain-http control plane unless `A2AGW_DEV=1`. The Docker example has an
optional `control-plane` service behind a compose profile
(`docker compose -f examples/docker/compose.yaml --profile control-plane up`).

`control.yaml` is loaded with the gateway's config rules: `${VAR}` and `${VAR:-default}`
read the environment, unknown keys are errors, errors name dotted field paths and never
values, and an inline secret (`client_secret: ...`, a password in `db_url`) is refused with
a hint to use `*_env`.

| Key | Default | What |
|---|---|---|
| `base_url` | required | the public URL of the control plane (the OIDC redirect is built from it) |
| `db_url` | `sqlite+aiosqlite:///a2agw-control.db` | SQLite for one replica, PostgreSQL for several |
| `oidc` | none | `{issuer, client_id, client_secret_env, scopes, roles_claim, role_map}`: sign-in for people |
| `session` | `{absolute_s: 28800, idle_s: 3600, cookie_secure: true}` | Console sessions |
| `retention` | `{events_days: 7, commands_days: 7}` | see [Retention](#retention) |
| `limits` | `{report_max_bytes: 1048576, report_max_items: 1000, stream_keepalive_s: 15}` | what gateways may send, and the stream keepalive |
| `trust` | none | the gateway's `trust` shape: keys for partner card signatures (`require_signed` tiers) |

**Sign-in.** People sign in through the OIDC provider (authorization code flow with PKCE,
run by the control plane itself: the browser never holds a token). The ID token is checked
(`iss`, `aud`, `exp`, `nonce`, signature from the provider's JWKS) and the user's roles are
re-derived from `roles_claim` through `role_map` at every sign-in: a user with no mapped
group has no permission. A session is the `a2agw_session` cookie (HttpOnly, Secure,
SameSite=Lax); `GET /api/v1/me` answers `{id, name, email, roles, permissions,
csrf_token}`, and every session request that is not GET/HEAD/OPTIONS must send that token
in `X-A2AGW-CSRF` (403 `csrf` otherwise). `POST /auth/logout` ends the session. Every call
to the provider goes through the SSRF guard at the `partner` tier.

**API keys** are for automation: `Authorization: Bearer <key>`, with one role each, and not
subject to CSRF. Bootstrap the first admin key with
`a2agw control create-api-key --name bootstrap --role admin -c control.yaml` (printed once);
later keys come from `POST /api/v1/api-keys`, whose role must not carry a permission the
caller lacks. `a2agw control create-gateway --name N` registers a gateway from the command
line the same way. Keys, gateway tokens, session ids and CSRF tokens are stored only as
SHA-256 digests; the one response that creates a key or a token is the only place it is
ever shown.

## Roles and permissions

A user or key with several roles gets the union of their permissions.

| Permission | What it allows | viewer | operator | security | admin |
|---|---|:-:|:-:|:-:|:-:|
| `read` | every read view, the catalogue, the policies, command status, the OpenAPI document | yes | yes | yes | yes |
| `tasks.operate` | cancel, answer, reap, refresh a partner on one gateway |  | yes |  | yes |
| `partners.trust` | approve, reject, quarantine partners; change their tier, refs and tags |  |  | yes | yes |
| `policy.edit` | save policy versions, dry-run |  |  | yes | yes |
| `audit.read` | the audit views, export and chain check |  |  | yes | yes |
| `partners.register` | register a partner, refresh its card |  |  |  | yes |
| `assign` | assign partners and policies to gateways |  |  |  | yes |
| `gateways.manage` | register, list, rotate and revoke gateways |  |  |  | yes |
| `users.manage` | list users, disable them |  |  |  | yes |
| `apikeys.manage` | create, list and revoke API keys |  |  |  | yes |
| `settings.manage` | read the effective settings |  |  |  | yes |

No credentials is a 401; a missing permission is a 403 `forbidden`, audited as `cp.denied`
(coalesced per actor and permission). The `/cp/v1` routes take gateway tokens only: a
session or an API key never passes there, and a gateway token never passes on `/api/v1`.

## API overview

The OpenAPI document is `GET /api/openapi.json` (permission `read`); the interactive docs
are off. Errors have one shape, `{"error": "<code>", "detail": "<message>"}`; a validation
error is a 422 whose `fields` are dotted paths of the offending inputs, never their values,
and an unexpected failure is a bare 500 `internal` (the log has its class and the
`X-Request-ID`, never its message). Lists answer `{items, next_cursor}` (see
[Console read API](#console-read-api)).

| Area | Routes | Permission |
|---|---|---|
| Health | `GET /healthz` | public |
| Sign-in | `GET /auth/login`, `GET /auth/callback`, `POST /auth/logout`, `GET /api/v1/me` | public (the last two need a session) |
| Gateways | `GET`/`POST /api/v1/gateways`, `POST /api/v1/gateways/{id}/tokens`, `POST /api/v1/gateways/{id}/revoke` | `gateways.manage` |
| Assignment | `PUT /api/v1/gateways/{id}/partners`, `PUT /api/v1/gateways/{id}/policy` | `assign` |
| Catalogue | `GET /api/v1/partners`, `GET /api/v1/partners/{id}` | `read` |
| | `POST /api/v1/partners`, `POST /api/v1/partners/{id}/refresh` | `partners.register` |
| | `POST /api/v1/partners/{id}/approve`, `.../reject`, `.../quarantine`, `PUT .../settings` | `partners.trust` |
| Policies | `GET /api/v1/policies`, `GET /api/v1/policies/{id}` | `read` |
| | `POST /api/v1/policies`, `POST /api/v1/policies/{id}/versions`, `POST /api/v1/policies/dry-run` | `policy.edit` |
| Operator actions | `POST /api/v1/tasks/{gw}/{agent}/{task}/cancel`, `.../answer`, `POST /api/v1/gateways/{id}/reap`, `POST /api/v1/partners/{id}/gateways/{gw}/refresh` | `tasks.operate` |
| | `GET /api/v1/commands/{id}` | `read` |
| Read views | `GET /api/v1/overview`, `/agents`, `/tasks`, `/tasks/{gw}/{agent}/{task}`, `/topology`, `/credentials` | `read` |
| Audit | `GET /api/v1/audit`, `/audit/export`, `/audit/verify` | `audit.read` |
| Users and keys | `GET /api/v1/users`, `PATCH /api/v1/users/{id}` | `users.manage` |
| | `GET`/`POST /api/v1/api-keys`, `POST /api/v1/api-keys/{id}/revoke` | `apikeys.manage` |
| Settings | `GET /api/v1/settings` (read-only) | `settings.manage` |
| Gateway channel | `GET /cp/v1/stream`, `POST /cp/v1/report` | gateway token |

## Managed and local mode

Without a `control_plane` section a gateway is in local mode and behaves exactly as before:
its partners come from `partners:` and the partners file, its policy from `policy_file`
(or the admin API), and nothing connects out. With a `control_plane` section it is managed
for the sections listed in `manage` (both by default):

- `manage: [partners, policy]`: the control plane owns both. The gateway has no partners
  file, `partners:` and `policy_file` are configuration errors, the `a2agw partners`
  commands do not apply, and `PUT /a2agw/admin/policy` answers 409.
- `manage: [partners]`: the catalogue owns the partners; the policy stays local
  (`policy_file` or the admin API).
- `manage: [policy]`: the control plane owns the policy; partners stay local.

Either way a managed gateway connects, reports events, audit rows, health and metrics, and
runs operator commands. Everything not managed (agents, auth, limits, TLS, credentials,
telemetry) stays in the gateway's own config file.

## Gateways

### Enrolling a gateway

1. Register the gateway on the control plane: `POST /api/v1/gateways {"name": "eu-1"}`
   (permission `gateways.manage`) answers `{id, name, token}` (or, on the control plane's
   host, `a2agw control create-gateway --name eu-1 -c control.yaml`). The token is shown
   only there; the control plane keeps its SHA-256 digest.
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
(never the token) and `/a2agw/admin/healthz` shows `last_error_kind: "unauthorized"` from
then on (a stream that ends afterwards does not replace it). It keeps serving its last
applied state. Restart it with the new token; a revoked gateway is gone for good (register
it again).

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
`args`, `expires_at` and `actor`; see [Operator actions](#operator-actions) for the routes
that queue them). Each runs the gateway's shared write operation
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
  gateway info `{version, agents, base_url, limits}`. `limits` are the gateway's effective
  limits (`max_concurrent_tasks_per_caller`, `max_consults_per_task`,
  `max_open_sidecar_tasks_per_caller`, `max_body_bytes`, `max_parts`), shown read-only in
  the gateway list (`info.limits`); the control plane keeps those names with numbers only.
  Each agent is `{id, name, version, skills, card_url}` from the hosted agent's spec (the
  source of its card): at most 200 agents and 64 skill ids each, strings cut to 256
  characters. The control plane also accepts the older form, a list of agent ids, and
  stores it with the other fields null.

`partner.call` events name the agent whose turn made the call (`agent_id`), so a topology
edge is (gateway, calling agent, partner).

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

## Operator actions

Each action is queued as a command for one gateway (see [Commands](#commands)), audited as
`cp.command` (the operator, the gateway and the kind; never an answer's text), and
expires 60 s after it is queued.

| Route | Command |
|---|---|
| `POST /api/v1/tasks/{gateway}/{agent}/{task}/cancel` | `task.cancel`: the task and the partner tasks it started |
| `POST /api/v1/tasks/{gateway}/{agent}/{task}/answer` `{text}` | `task.answer`: only an `input-required` task (`auth-required` is refused); `text` at most 32 KiB |
| `POST /api/v1/gateways/{gateway}/reap` `{agent_id, confirm?, force?}` | `tasks.reap` |
| `POST /api/v1/partners/{id}/gateways/{gateway}/refresh` | `partner.refresh` on that gateway (a change quarantines there) |

The request waits up to 10 s for the gateway (no database connection is held meanwhile):

- 200 `{command_id, status: "done", result}`;
- 409 `{command_id, status: "failed" | "expired", result}` when the gateway reports a
  failure (`not_found`, `conflict`, ...) or the command expired before delivery;
- 202 `{command_id, status: "pending" | "delivered"}` otherwise. Follow it with
  `GET /api/v1/commands/{id}` (`read`), which shows who queued it as a kind only (`console`
  or `key`).

At most 16 requests wait at once per process; the others answer 202 at once. A command is
delivered at most once and never after it expired. A delivered command stays `delivered`
until the gateway reports it, or until the maintenance pass marks it `expired` after its
TTL; a result that arrives after that is ignored.

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

## Retention

The maintenance pass (every 60 s, in every replica) expires commands past their TTL, then
deletes in batches:

- gateway events (`cp_events`) older than `retention.events_days` (7). Every read view
  (tasks, overview, topology, timelines) is computed from these events, so it covers at
  most that window;
- finished commands, results included, `retention.commands_days` (7) after they finished.
  `task.get` results hold clipped message text;
- expired sessions and sign-in states.

Audit rows are never deleted by the control plane: its own chain (`cp_audit`) and the
gateway rows it copied (`cp_gateway_audit`) stay until you archive them
(`GET /api/v1/audit/export`) and prune the database yourself. A gateway's own audit log
lives in the gateway's database.

## Running several replicas

Several control-plane replicas can serve one PostgreSQL database (SQLite is for one
replica). There is no messaging between replicas: everything goes through the database.

- **Streams poll the store.** Each gateway stream polls the database every 0.5 s for its
  desired state and its commands, so a change made on any replica reaches the gateway at
  its stream's next poll, whichever replica holds the stream. Reports can land on any
  replica.
- **Shared state is in the database**: sessions, sign-in states (so a sign-in may start on
  one replica and finish on another), API keys, gateway tokens, the commands queue, the
  desired state and its versions. Version bumps are compare-and-set, so concurrent
  recomputes bump once.
- **Per process**: the task-detail sharing and its waiter cap (two replicas asked for the
  same task's detail at once may each queue a `task.get`), the operator-action waiter cap,
  the OIDC discovery and JWKS caches, and the `last_seen_at` write throttle.
- **Consult tokens stay per gateway process.** They are the gateway's, not the control
  plane's: a sidecar agent's call to `consult_url` must still reach the gateway process
  that issued its token (see the README's known limitations).

## Known limitations

Accepted for Phase 4a:

- **Single tenant.** One control plane serves one organization. The spec's tenants
  (Settings screen) are deferred, and the tables have no tenant column yet.
- **Limits and budgets aren't policy yet.** The spec's Policies screen covers "limits,
  budgets", but the gateway keeps limits in its config file (`limits:`), not in the policy
  document, and token or cost budgets aren't enforced yet (§11a.3). The control plane shows
  each gateway's effective limits read-only (from `info`); distributing them is deferred.
- **Settings are file-managed.** `GET /api/v1/settings` is read-only.
- **Traces are only as good as the events.** The timeline comes from forwarded events, not
  OTel spans; a full span view needs an OTLP backend. Trace ids exist only where the
  gateway runs with an OpenTelemetry tracer provider (`telemetry:`); without one, a
  timeline joins gateways only through the partner tasks in a task's detail.
- **Egress content checks can't be replayed** in the dry-run: the message text is never
  stored.
- **Answering `auth-required` prompts from the Console is refused** by design.

Also:

- **Audit chain breaks**: no gateway reports a chain check yet, so there is no alert for a
  broken gateway chain. Verify a gateway's chain on the gateway (`a2agw audit verify`).
- **Credential references** come from the catalogue only: gateways do not report the
  credential or TLS reference names they hold.
- Partner calls reported by gateways older than the `trace_id` field join a task's timeline
  only through the partner tasks in its detail.
- **Registering is an admin permission.** `partners.register` belongs to admin only;
  security reviews and trusts (approve, reject, quarantine) what an admin registered.
