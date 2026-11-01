# Control plane

The control plane (`a2agw.control`, the `control` extra) owns the partner catalogue, the
policies, the users and roles of the Console, and the list of gateways. Gateways connect out
to it; it never calls a gateway.

This document is filled in as Phase 4a lands. The sections on deployment, roles and the
`/api/v1` API follow with the tasks that build them.

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
| `task.get` | `agent_id, task_id` | the task's detail |
| `partner.refresh` | `id` | re-fetch the partner's card now |
| `partner.approve` | `id, expected_hash` | approve a quarantined card change with that hash |
| `partner.reject` | `id` | refuse a quarantined card change (the partner is disabled) |
| `tasks.reap` | `agent_id, confirm?, force?` | fail the open tasks of an agent nobody serves |

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
- command results, and the outcome of each state applied or rejected;
- every `health_interval_s`: health, the metrics snapshot (`/a2agw/admin/metrics`) and the
  gateway info `{version, agents, base_url}`.

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

## Partner catalogue

The catalogue is the central registry: each partner is registered once and assigned to the
gateways that use it. A partner's status is `pending` (nothing approved yet), `approved`,
`quarantined` or `rejected`; only an approved partner is sent to its gateways, as its
approved card version. Every write is audited in `cp_audit`.

| Route | Permission | What it does |
|---|---|---|
| `POST /api/v1/partners` `{id, card_url \| card, tier, credential_ref?, tls_ref?, tags?}` | `partners.register` | fetch the card (SSRF-guarded for the tier), validate and verify it; version 1, `pending` |
| `GET /api/v1/partners?tier=&status=&gateway_id=&q=` | `read` | the list; `q` is the skill search |
| `GET /api/v1/partners/{id}` | `read` | approved card, pending card, their `diff`, the versions, what each gateway reported |
| `POST /api/v1/partners/{id}/approve` `{version, expected_hash}` | `partners.trust` | approve that version (409 if the hash differs) |
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
  it holds. Only that hash is taken from a gateway, never a card. Approving the version with
  that hash also queues `partner.approve {id, expected_hash}` for those gateways.
- **References only.** `credential_ref` and `tls_ref` are names each gateway resolves from
  its own configuration. The control plane holds no partner secret, and it fetches cards
  without a client certificate: register an mTLS-only partner with its card inline.
