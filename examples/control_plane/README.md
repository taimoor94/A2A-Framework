# Control plane walkthrough: one control plane, two gateways

This walkthrough runs a control plane and two managed gateways on one machine, then does
the Console's operations through `/api/v1` with `curl` and `jq`. `gw-east` hosts
`planner`; `gw-west` hosts `p`, which the control plane registers as a partner and assigns
to both gateways. The same story runs as one test:
`tests/integration/test_phase4a_control_plane.py`.

Files:

- `control.yaml`: the control plane (SQLite; sign-in through OIDC commented out, so this
  walkthrough uses API keys).
- `gw-east.yaml`, `gw-west.yaml`: two gateways with `control_plane:` sections that manage
  their partners and policy.
- `walkthrough_agents.py`: the two agents.

Everything here is plain http on `localhost`, which the gateways and the control plane
accept only with `A2AGW_DEV=1`. Use https everywhere else. Secrets (the gateway tokens and
API keys) are only ever in environment variables, never in a config file.

## 1. Start the control plane and make an admin key

```bash
pip install 'a2a-gateway[control]'
export A2AGW_DEV=1
a2agw control serve -c examples/control_plane/control.yaml        # terminal 1, port 8100
```

In another terminal, create the first admin key (printed once; only its digest is stored)
and register the two gateways. Each `POST /api/v1/gateways` answers the gateway's token,
also shown only once:

```bash
export A2AGW_DEV=1 CP=http://localhost:8100
a2agw control create-api-key --name bootstrap --role admin -c examples/control_plane/control.yaml
export ADMIN_KEY=...                                           # the key it printed
H="Authorization: Bearer $ADMIN_KEY"
EAST=$(curl -s -X POST -H "$H" -H 'content-type: application/json' $CP/api/v1/gateways -d '{"name": "gw-east"}')
WEST=$(curl -s -X POST -H "$H" -H 'content-type: application/json' $CP/api/v1/gateways -d '{"name": "gw-west"}')
EAST_ID=$(jq -r .id <<<"$EAST"); WEST_ID=$(jq -r .id <<<"$WEST")
```

Make a key per role for the people and scripts that will use it (a key's role can never
carry a permission its creator lacks):

```bash
for role in viewer operator security; do
  curl -s -X POST -H "$H" -H 'content-type: application/json' $CP/api/v1/api-keys \
    -d "{\"name\": \"$role\", \"role\": \"$role\"}" | jq -r .key
done
```

## 2. Start the gateways

Each gateway reads its token from `A2AGW_CP_TOKEN` (the `token_env` of its config):

```bash
A2AGW_DEV=1 A2AGW_CP_TOKEN=$(jq -r .token <<<"$EAST") \
  a2agw serve -c examples/control_plane/gw-east.yaml --port 8001   # terminal 2
A2AGW_DEV=1 A2AGW_CP_TOKEN=$(jq -r .token <<<"$WEST") \
  a2agw serve -c examples/control_plane/gw-west.yaml --port 8002   # terminal 3
```

They connect, but no policy is assigned yet, so both are locked down (`cp:unconfigured`
denies every call). `curl localhost:8001/a2agw/admin/healthz` shows the connection and the
warning.

## 3. Register and approve the partner

Registering needs `partners.register` (admin); approving needs `partners.trust` (security
or admin). The approval names the hash of the card that was reviewed: if the card changed
in between, it is a 409.

```bash
P=$(curl -s -X POST -H "$H" -H 'content-type: application/json' $CP/api/v1/partners \
  -d '{"id": "p", "tier": "internal", "card_url": "http://localhost:8002/agents/p"}')
HASH=$(jq -r '.versions[0].card_hash' <<<"$P")
curl -s -X POST -H "$H" -H 'content-type: application/json' $CP/api/v1/partners/p/approve \
  -d "{\"version\": 1, \"expected_hash\": \"$HASH\"}" | jq .status
```

The `internal` tier allows loopback addresses, which is right here (you run `p`
yourself); use `partner` or `public` for anyone else's agent.

## 4. Assign the partner and a policy

```bash
POLICY=$(curl -s -X POST -H "$H" -H 'content-type: application/json' $CP/api/v1/policies \
  -d '{"name": "open", "doc": {"version": 1, "authz": [{"id": "anon", "principal": "anonymous", "agents": "*", "effect": "allow"}]}}')
for gw in $EAST_ID $WEST_ID; do
  curl -s -X PUT -H "$H" -H 'content-type: application/json' $CP/api/v1/gateways/$gw/partners -d '{"partner_ids": ["p"]}'
  curl -s -X PUT -H "$H" -H 'content-type: application/json' $CP/api/v1/gateways/$gw/policy \
    -d "{\"policy_id\": $(jq .id <<<"$POLICY"), \"version\": null}"
done
curl -s -H "$H" $CP/api/v1/gateways | jq '.gateways[] | {name, version_applied, version_desired}'
```

`version: null` follows the policy's latest version; a number pins one. Once
`version_applied` equals `version_desired`, both gateways run with `p` and the policy.

Before tightening a policy, replay the last days of traffic against the candidate:

```bash
curl -s -X POST -H "$H" -H 'content-type: application/json' $CP/api/v1/policies/dry-run \
  -d '{"doc": {"version": 1, "authz": [{"id": "anon", "principal": "anonymous", "agents": "*", "effect": "allow"}, {"id": "no-p", "principal": "*", "agents": ["p"], "effect": "deny"}]}}' \
  | jq '{counts, newly_blocked: [.newly_blocked[] | {gateway_id, agent_id, rule}]}'
```

## 5. Watch, operate, audit

```bash
curl -s -H "$H" $CP/api/v1/overview | jq .
curl -s -H "$H" "$CP/api/v1/tasks?limit=20" | jq .items
curl -s -H "$H" "$CP/api/v1/topology?window_m=60" | jq .edges
curl -s -H "$H" "$CP/api/v1/tasks/$EAST_ID/planner/<task id>" | jq .timeline
curl -s -X POST -H "$H" "$CP/api/v1/tasks/$EAST_ID/planner/<task id>/cancel"
curl -s -X POST -H "$H" -H 'content-type: application/json' \
  "$CP/api/v1/tasks/$WEST_ID/<agent>/<task id>/answer" -d '{"text": "yes"}'
curl -s -H "$H" "$CP/api/v1/audit/export?format=csv" > audit.csv
curl -s -H "$H" $CP/api/v1/audit/verify
```

Operator actions are commands the gateway runs; an answer of 202 carries a `command_id` to
follow with `GET /api/v1/commands/{id}`.

## 6. Fail static and revocation

Stop the control plane: both gateways keep serving with what they applied, and resend
their unacknowledged audit rows once it is back. Revoke a gateway with
`POST /api/v1/gateways/$WEST_ID/revoke`: its stream ends, its connector stops with
`last_error_kind: "unauthorized"` in its healthz, and it keeps serving its last applied
state. Revocation is final: register the gateway again to bring it back. To replace a
leaked token without revoking the gateway, rotate it (`POST /api/v1/gateways/{id}/tokens`)
and restart the gateway with the new one.

See [docs/control-plane.md](../../docs/control-plane.md) for every route, the roles and
what each failure does.
