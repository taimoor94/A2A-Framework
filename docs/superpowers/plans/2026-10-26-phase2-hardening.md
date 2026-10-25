# A2A Gateway Framework — Phase 2 (Hardening) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `a2agw` safe to run against untrusted, global partners in production. This phase adds signed agent cards, OAuth2 and mTLS, a declarative policy engine (authorization, egress and routing), a tamper-evident audit log, push notifications, PostgreSQL, DNS-rebinding-proof outbound connections, signed call contexts between gateways, and a test suite that covers boundary conditions 1–13.

**Architecture:** Phase 2 extends the Phase 1 modules in place:

- `security/` gains card signing, the policy engine and call-context signing.
- `consult/` gains OAuth credentials, mTLS and a guarded network backend.
- `ops/` gains the audit log.
- `serve/` gains push notifications and Postgres support.

Every new capability is opt-in through `AgentHost` keyword arguments and `a2agw.yaml`. With nothing configured, Phase 1 behaviour is unchanged.

**Tech Stack:**

- Existing: `a2a-sdk` 1.2.x (`a2a.utils.signing`, `BasePushNotificationSender`, `DatabasePushNotificationConfigStore`), httpx/httpcore, PyJWT[crypto], cryptography, SQLAlchemy async.
- New optional extra `postgres = ["asyncpg>=0.30"]`.
- Local PostgreSQL 16 for tests: `/opt/homebrew/opt/postgresql@16/bin`. Tests skip if it isn't found.

**Spec:** `docs/superpowers/specs/2026-10-25-a2a-gateway-framework-design.md`. These sections apply: §7.3 (signed cards, quarantine), §7.4 (call context), §7.5 (security and trust: every bullet), §7.6, §8 (boundary conditions 1–13), §9 Phase 2, §10 (testing strategy), and §11a items 2, 4, 6.

**Prior plan, for conventions:** `docs/superpowers/plans/2026-10-25-phase1-core.md`. Its Global Constraints still apply.

## Global Constraints

- **Inherited from Phase 1.** All Phase 1 global constraints and rulings still apply (R1–R6, prefixed principals `key:`/`jwt:`, the 64 KiB partner text cap, `max_hops=8`, and so on). No Phase 1 public signature may change incompatibly. New parameters are keyword-only with defaults that preserve current behaviour.
- **Fail closed.** Every new verification step fails closed. A bad signature, a bad token, a policy evaluation error, or a failed DNS check all deny the action and do not fall back to allow.
- **No secrets in the audit log.** The audit log never stores secrets, message text or artifact contents: only ids, names, classifications, decisions and reasons.
- **Key material comes from files or env vars named in config.** It is never inline in YAML and never logged. Private keys are PEM. Allowed algorithms are `ES256`, `RS256` and `EdDSA` only.
- **Database URLs:** `sqlite+aiosqlite:///…` (default) or `postgresql+asyncpg://…`. Every SQL path must work on both.
- **Postgres tests** are marked `@pytest.mark.postgres`. They run against a throwaway cluster started by a session fixture, and they skip cleanly when `pg_ctl` is unavailable. They are included in the default run.
- **TCK.** After Task 6, `scripts/run_tck.sh` MUST shows 0 failures, and the push-notification tests are no longer skipped.
- **Commits.** Commit to `main` after each task's review passes. Run the full suite (`uv run pytest -q -W error`) and `uv run ruff check` before every commit.

## Review Focus

1. **A partner card signed with a key we don't trust, or with alg `none`/HS256** must be rejected or quarantined, never accepted as signed. Covered by a test in Task 1.
2. **An expired or revoked OAuth token mid-conversation** gives one refresh and one resend on HTTP 401 before the task exists. A 401 after acceptance is never resent. Covered by a test in Task 2.
3. **A DNS answer that changes between check and connect** (rebinding to 169.254.169.254) means the connection goes only to the vetted IP, or fails. Covered by a test in Task 8.
4. **A push-notification webhook pointing at a private IP, or redirecting to one,** is refused at config time and at delivery time. Covered by a test in Task 6.
5. **A policy file with a typo or an unknown field** stops startup with a clear error naming the field. It is never silently ignored. Covered by a test in Task 4.

---

## File structure (new or changed)

```
src/a2agw/security/cardsign.py       CardSigner, CardVerifier, key loading
src/a2agw/security/policy.py         Policy model + PolicyEngine (authz, egress, routing)
src/a2agw/security/classify.py       Classification levels, Classifier protocol, RegexPiiClassifier
src/a2agw/context/signing.py         CallContextSigner / Verifier (JWS over call context)
src/a2agw/consult/oauth.py           OAuthClientCredentials, OAuthTokenExchange providers
src/a2agw/consult/tls.py             per-partner mTLS client config
src/a2agw/consult/guarded_net.py     GuardedBackend (httpcore network backend pinning vetted IPs)
src/a2agw/ops/audit.py               AuditLog (hash-chained table), AuditEvent
src/a2agw/serve/push.py              push config store + guarded sender wiring
(modified) serve/host.py, serve/agent.py, serve/executor.py, serve/store.py,
           consult/registry.py, consult/client.py, consult/tools.py, consult/handles.py,
           config.py, cli.py, ops/admin.py, README.md, docs/conformance.md
tests/postgres_support.py            throwaway cluster fixture
docs/boundary-conditions.md          §8 matrix → tests
```

---

### Task 1: Signed agent cards (sign inbound, verify outbound)

**Files:**
- Create `src/a2agw/security/cardsign.py`.
- Modify `serve/host.py` (signing built cards), `consult/registry.py` (verification and policy).
- Tests: `tests/security/test_cardsign.py`, `tests/consult/test_registry.py`.

**Interfaces:**
- Consumes the SDK functions `a2a.utils.signing.create_agent_card_signer(signing_key, protected_header, header=None)` and `create_signature_verifier(key_provider, algorithms)`, plus `NoSignatureError` and `InvalidSignaturesError`.
- Produces:
  - `load_private_key(pem_path: Path) -> PyJWK`.
  - `CardSigner(key_path: Path, kid: str, alg: Literal["ES256","RS256","EdDSA"], jku: str | None = None)`, whose `.sign(card: AgentCard) -> AgentCard` adds one `AgentCardSignature`.
  - `CardVerifier(trusted: dict[str, PyJWK] | None = None, jwks_urls: list[str] = [], http: httpx.AsyncClient | None = None)`, whose `async .verify(card: AgentCard) -> str` returns the kid that verified, or raises `CardSignatureError(reason)`.
    - Keys come from `trusted` by kid, or from a `jku` that is in `jwks_urls` (an allowlist). A `jku` outside the allowlist is ignored.
    - JWKS fetches go through `check_url(..., "public")` with a 1 MiB cap and a 10 s total deadline, and are cached for 300 s.
    - Algorithms are restricted to `["ES256","RS256","EdDSA"]`.
  - `AgentHost(..., card_signer: CardSigner | None = None)` signs every built card before serving it.
  - `PartnerRegistry(..., verifier: CardVerifier | None = None, require_signed: frozenset[Tier] = frozenset())`.
    - When the tier is in `require_signed`, `add_*` and `refresh` verify the card. On failure, `add_*` raises `CardFetchError("card signature invalid")`, and `refresh` quarantines the partner.
    - `PartnerRecord` gains `signed_kid: str | None`.
    - A change of signing key (a different kid) counts as a significant change and quarantines the partner.

- [ ] **Step 1:** Write the tests:
  - `test_sign_then_verify_roundtrip_es256_and_eddsa`
  - `test_verify_rejects_tampered_card` (change the description after signing)
  - `test_verify_rejects_unknown_kid`
  - `test_verify_rejects_alg_none_and_hs256` (a hand-built signature)
  - `test_jku_outside_allowlist_ignored`
  - `test_jwks_fetch_ssrf_guarded` (`jku` set to `http://169.254.169.254/` raises `CardSignatureError`)
  - `test_host_serves_signed_card` (the served JSON has `signatures` and verifies)
  - `test_registry_requires_signature_for_public_tier`
  - `test_refresh_with_new_kid_quarantines`
- [ ] **Step 2:** Run them and see them fail.
- [ ] **Step 3:** Implement. Canonicalization is the SDK's. Never re-implement JCS.
- [ ] **Step 4:** Run the tests until they pass. Commit with the message `feat(security): signed agent cards`.

### Task 2: OAuth2 outbound credentials (client credentials and token exchange)

**Files:**
- Create `src/a2agw/consult/oauth.py`.
- Modify `consult/client.py` (one resend on 401 before acceptance) and `consult/handles.py` (caller id column).
- Tests: `tests/consult/test_oauth.py`, `tests/consult/test_client.py`.

**Interfaces:**
- Consumes the `CredentialProvider` protocol `async headers(partner, caller) -> dict[str,str]` and `check_url`.
- Produces:
  - `OAuthClientCredentials(token_url: str, client_id: str, client_secret_env: str, scope: str | None = None, audience: str | None = None, refs: set[str] | None = None, http=None)`.
    - It returns `{"Authorization": "Bearer <tok>"}` for partners whose `credential_ref` is in `refs`, or for all partners when `refs` is None.
    - The token is cached until 30 s before `exp` or `expires_in`.
    - Refreshes are single-flight (an `asyncio.Lock`).
    - `token_url` must pass `check_url(..., "public")`. This closes the deferred Phase 1 item about unchecked token URLs.
    - It exposes `invalidate(partner)`.
  - `OAuthTokenExchange(token_url, client_id, client_secret_env, audience, refs=None)`. This implements RFC 8693: it exchanges the inbound caller's JWT for a partner-audience token.
    - The inbound raw bearer token is made available only through a new contextvar `current_inbound_token: ContextVar[str | None]` in `a2agw.context.call_context`. It is set by `GatewayAuthBackend` for the request and copied by the executor into the adapter run. It is never logged.
    - If no inbound token is present, it raises `MissingCredential`.
  - `PartnerClient` change: when a send fails with HTTP 401 before any event, and the provider has `invalidate`, call it, then resend once with the same `message_id`. This is safe because a 401 means the request was not accepted. Never resend after any event.
  - Handle rows gain a `caller_id` column (nullable). `cancel_for_inbound` and recovery cancels pass `Principal(id=caller_id, kind=<from prefix>)` as the caller, closing the deferred T15 item.
    - Migration: `OutboundHandleStore.initialize()` adds the column if it is missing (`ALTER TABLE … ADD COLUMN`) on both sqlite and postgres.

- [ ] **Step 1:** Write the tests, using `respx` for the token endpoint:
  - `test_client_credentials_caches_until_expiry`
  - `test_single_flight_refresh` (10 concurrent callers make 1 token request)
  - `test_token_url_ssrf_rejected`
  - `test_secret_never_in_repr_or_errors`
  - `test_401_before_accept_refreshes_and_resends_once` (the partner sees two sends with the same messageId; the second carries the new token)
  - `test_401_twice_gives_auth_required_result` (state `auth_required`, reason "partner rejected credentials")
  - `test_token_exchange_uses_inbound_token` (an end-to-end host: the inbound JWT's subject reaches the token endpoint form as `subject_token`)
  - `test_cascade_cancel_uses_original_caller`
  - `test_handles_migration_adds_caller_id`
- [ ] **Step 2:** Run them and see them fail.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the tests until they pass. Commit with the message `feat(consult): OAuth2 credentials, 401 refresh, caller-scoped cascade`.

### Task 3: mTLS (outbound per partner, inbound at the server)

**Files:**
- Create `src/a2agw/consult/tls.py`.
- Modify `consult/client.py`, `consult/registry.py` (the record field), `serve/host.py` (`run`) and `cli.py` (`serve` flags).
- Test: `tests/consult/test_tls.py`.

**Interfaces:**
- Produces:
  - `TlsClientConfig(cert_file: Path, key_file: Path, ca_file: Path | None = None)`, whose `ssl_context() -> ssl.SSLContext` uses TLS 1.2 or later with hostname checks on.
  - `PartnerRecord` gains `tls_ref: str | None`.
  - `PartnerClient(..., tls: dict[str, TlsClientConfig] = {})` uses a dedicated `httpx.AsyncClient(verify=ctx)` per `tls_ref`, with `cert` loaded into the context. These clients are cached and closed in `aclose`.
  - Inbound: `AgentHost.run(..., ssl_certfile=None, ssl_keyfile=None, ssl_ca_certs=None, require_client_cert=False)` passes these through to uvicorn (`ssl_cert_reqs=ssl.CERT_REQUIRED` when `require_client_cert`).
    - `a2agw serve` gains the matching `--ssl-*` flags and `--require-client-cert`.
    - Document that the client certificate is checked at the TLS layer, but identity still comes from the API key or JWT. ASGI servers don't expose peer certificates.
- Tests:
  - Generate a throwaway CA, a server cert and a client cert with `cryptography` in a fixture.
  - Run a real uvicorn on 127.0.0.1 with `require_client_cert=True`.
  - `test_partner_with_client_cert_succeeds`
  - `test_partner_without_client_cert_fails_unavailable`
  - `test_wrong_ca_fails`
  - `test_tls_clients_closed_on_aclose`
- [ ] Steps as above: fail, implement, pass. Commit with the message `feat: mTLS for partners and server`.

### Task 4: Data classification and the policy engine (model and evaluation)

**Files:**
- Create `src/a2agw/security/classify.py` and `src/a2agw/security/policy.py`.
- Tests: `tests/security/test_classify.py`, `tests/security/test_policy.py`.

**Interfaces:**
- Produces:
  - `Classification` is an ordered enum: `public < internal < confidential < restricted`.
  - `class Classifier(Protocol): def classify(self, text: str, data: dict | None) -> Classification`.
  - `RegexPiiClassifier()` detects email addresses, phone numbers, IBAN-like strings and credit-card numbers (Luhn-checked), and returns `confidential`. Otherwise it returns `public`. It is off by default (spec §11a item 6).
  - `Policy` is a Pydantic model with `extra="forbid"` and a `version: Literal[1]` field. It contains:
    - `authz`: rules shaped `{principal: str (exact id, or "*"; "*" never matches anonymous), agents: list[str] | "*", skills: list[str] | "*", effect: allow|deny}`. Evaluation is deny-overrides and default-deny when any authz rule exists for the agent. With no rules, Phase 1 `AgentAccess` behaviour holds.
    - `egress`: per-tier ceilings (default `internal: restricted, partner: confidential, public: public`) and per-partner overrides.
    - `routing`: rules shaped `{agent: str, match: {tags_any: list[str] | None, skills_any: list[str] | None}, partners: list[str], mode: force|prefer|forbid}`.
    - `defaults`: `{agent_classification: dict[agent_id, Classification]}`.
  - `PolicyEngine(policy: Policy, classifier: Classifier | None = None)` has these methods:
    - `authorize(principal: Principal | None, agent_id: str, skill_id: str | None) -> Decision`
    - `egress(agent_id: str, partner: PartnerRecord, classification: Classification | None, text: str, data: dict | None) -> Decision`. The effective classification is the max of the explicit value, the agent default and the classifier's result.
    - `route(agent_id: str, partners: list[PartnerRecord]) -> RoutePlan`, which returns `visible`, `forced` and `preferred` partner id lists.
  - `Decision(allowed: bool, reason: str, rule: str | None, classification: Classification | None)`.
  - `load_policy(path: Path) -> Policy` reads YAML with `extra="forbid"`. Any validation error raises `PolicyError` naming the field path (Review Focus 5).
- Tests:
  - Table-driven tests for authz: wildcard, deny-overrides, anonymous never matched by `*`, and default-deny once rules exist.
  - Egress ceilings: PII text sent to a `public` partner is denied; an explicit `restricted` classification to a `partner`-tier partner is denied; an override raises a single partner's ceiling.
  - Routing: forbid hides a partner, force reports the forced partner, and prefer orders partners.
  - `test_unknown_field_rejected_with_path`.
  - `test_luhn_false_positive_not_flagged`.
- [ ] Steps: write the failing tests, implement, pass. Commit with the message `feat(security): classification and policy engine`.

### Task 5: Policy wiring and the audit log

**Files:**
- Create `src/a2agw/ops/audit.py`.
- Modify `serve/host.py`, `serve/executor.py`, `consult/client.py`, `consult/tools.py`, `consult/registry.py` and `ops/admin.py`.
- Tests: `tests/ops/test_audit.py`, `tests/integration/test_policy_wiring.py`.

**Interfaces:**
- Consumes `PolicyEngine` and `Decision` (Task 4).
- Produces:
  - `AuditEvent(ts, actor: str, action: Literal["inbound.admit","inbound.reject","authz.deny","partner.call","egress.deny","partner.add","partner.quarantine","partner.approve","partner.disable","partner.enable","admin.read"], agent_id, partner_id, task_id, classification, outcome: str, detail: dict)`. `detail` holds ids and reasons only.
  - `AuditLog(engine)` writes to the table `a2agw_audit(seq PK autoincrement, ts, actor, action, agent_id, partner_id, task_id, classification, outcome, detail_json, prev_hash, hash)`. Its methods are:
    - `initialize()`.
    - `async append(ev) -> int`. The hash is `hash = sha256(prev_hash + canonical_json(row without hash))`, and appends are serialized by an `asyncio.Lock`.
    - `async query(filters, limit, cursor)`.
    - `async verify_chain() -> int | None`, which returns the first broken seq or None.
  - `AgentHost(..., policy: PolicyEngine | None = None, audit: bool = True)` wires the policy in:
    - Authz runs inside `_AgentAuthorizer`, after `AgentAccess`. Both must allow.
    - The executor checks skill-level authz once the skill is known. Phase 1 has no skill routing, so it passes `skill_id=None`.
    - Egress is checked in `PartnerClient.consult` before sending. A denial returns `state="rejected", reason="egress policy: <reason>"` and sends nothing.
    - `partner_tools(registry, *, policy=None, agent_id=None)` drops forbidden partners and adds the line `Preferred for: …` or `Required for: …` (forced) to the descriptions. The `ask_*` schema gains an optional `classification` enum.
  - Registry state changes, inbound admit/reject, authz denials, partner calls (outcome = result state) and admin reads all append audit events.
  - Admin gains `GET /a2agw/admin/audit?action=&agent=&partner=&limit=&cursor=` and `GET /a2agw/admin/audit/verify`.
  - The CLI gains `a2agw audit export [-c] [--since ISO]`, which writes JSONL to stdout, and `a2agw audit verify`.
- Tests:
  - The hash chain detects a tampered row (an UPDATE in raw SQL makes `verify_chain` return that seq).
  - Concurrent appends keep the chain consistent (50 tasks).
  - No message text appears in audit rows (use a marker).
  - Policy denial of an inbound call returns 403 and is audited.
  - Egress denial means no partner request is made (respx asserts zero calls) and the action is audited.
  - A forbidden partner is absent from `partner_tools`.
  - Admin audit requires the admin scope.
- [ ] Steps: fail, implement, pass. Commit with the message `feat: policy enforcement and tamper-evident audit log`.

### Task 6: Push notifications (inbound A2A)

**Files:**
- Create `src/a2agw/serve/push.py`.
- Modify `serve/host.py`, `serve/agent.py` (card capability), `docs/conformance.md` and `examples/tck_sut/sut_agent.py`.
- Tests: `tests/serve/test_push.py`.

**Interfaces:**
- Consumes the SDK's `DatabasePushNotificationConfigStore` and `BasePushNotificationSender(httpx_client, config_store, push_url_validator=...)`.
- Produces `AgentHost(..., push: PushSettings | None = None)` with `PushSettings(allow_private: bool = False, timeout_s: float = 10.0, max_retries: int = 3, jwt_signer: CardSigner | None = None)`:
  - The card capability `push_notifications=True` is set only when push is configured.
  - The URL validator is `check_url(url, "internal" if allow_private else "public")`. It runs at config creation and again at each delivery (Review Focus 4). Task 8 later moves deliveries onto the guarded backend; until then, the per-delivery re-check plus no-redirects is the protection.
  - Deliveries don't follow redirects and are retried with jittered backoff (base 0.5 s, 3 attempts) on 5xx and connect errors only.
  - Each delivery carries the per-config `token` header from the spec (`X-A2A-Notification-Token`). When `jwt_signer` is set, it also carries an `Authorization: Bearer <JWT>` signed by the gateway key, with claims `iss = base_url`, `aud = webhook url`, `iat`, `exp = iat + 300`, `task_id`, and `jti`.
  - Push config CRUD is owner-scoped through the SDK store's owner resolver. A test checks that another principal cannot read or delete a config.
- Tests:
  - A real webhook receiver as a second ASGI app on a real uvicorn port.
  - State changes are delivered in order, with the token header.
  - A private webhook URL is rejected at config time.
  - A webhook that redirects to a private IP is not followed.
  - A receiver that is down at first is retried and then succeeds.
  - Cross-principal config access gives TaskNotFound.
- [ ] Steps: fail, implement, pass.
- [ ] Re-run `scripts/run_tck.sh` at the MUST and SHOULD levels with push enabled in the SUT. The push tests must now run with 0 MUST failures. Update `docs/conformance.md`.
- [ ] Commit with the message `feat(serve): push notifications with guarded delivery`.

### Task 7: PostgreSQL support

**Files:**
- Modify `pyproject.toml` (extra `postgres`), `serve/store.py`, `consult/handles.py` and `ops/audit.py`.
- Create `tests/postgres_support.py`.
- Modify `tests/conftest.py` (marker and fixture).
- Tests: `tests/serve/test_postgres.py`.

**Interfaces:**
- Produces:
  - `create_engine(url)` accepts `postgresql+asyncpg://` URLs, with `pool_pre_ping=True` and `pool_size=10`.
  - All upserts already branch on dialect. Audit, handles and the index must work on both backends.
  - Session fixture `pg_url`:
    - It runs `initdb` into a tmp dir and `pg_ctl start` on a free port with `-c listen_addresses=127.0.0.1 -c unix_socket_directories=<tmp>`, creates the database `a2agw_test`, yields `postgresql+asyncpg://…@127.0.0.1:<port>/a2agw_test`, and stops the server at teardown.
    - It skips if `pg_ctl` isn't found on PATH or in `/opt/homebrew/opt/postgresql@16/bin`.
  - The `@pytest.mark.postgres` marker is registered in pyproject.
- Tests, parameterized over `[sqlite_url, pg_url]` with one fresh database or schema per test:
  - Run the existing `TaskIndex`, `recover_on_startup`, `OutboundHandleStore`, `AuditLog` and `AgentHost` restart tests against Postgres too.
  - `test_two_hosts_share_postgres` (two `AgentHost` instances with different agents on one database).
- [ ] Steps: fail, implement, pass. Commit with the message `feat: PostgreSQL backend`.

### Task 8: DNS-rebinding-proof outbound connections

**Files:**
- Create `src/a2agw/consult/guarded_net.py`.
- Modify `consult/client.py`, `consult/registry.py` (card fetch), `consult/oauth.py`, `serve/push.py` and `cli.py` (call).
- Tests: `tests/consult/test_guarded_net.py`.

**Interfaces:**
- Produces `GuardedBackend(tier_for_host: Callable[[str], Tier], resolver=None)`. It implements the `httpcore.AsyncNetworkBackend` interface by wrapping `httpcore.AnyIOBackend`:
  - `connect_tcp(host, port, …)` resolves the host itself, through the same resolver used by `check_url`.
  - It checks all the addresses with the netguard IP rules for the host's tier.
  - It connects to the first allowed address. If any address is disallowed for a non-internal tier, it raises `httpcore.ConnectError("unsafe address")`.
  - TLS SNI and the Host header still use the original hostname, because httpx passes `server_hostname` separately.
  - It is exposed as `guarded_async_client(tier_for_host, **httpx_kwargs) -> httpx.AsyncClient`, built with `transport=httpx.AsyncHTTPTransport(...)` with the backend injected. Check how httpx 0.28 / httpcore 1.0 let a pool take a custom `network_backend` (`httpcore.AsyncConnectionPool(network_backend=…)`). If httpx doesn't expose it, build the transport around a pool you construct, and document it.
- Every outbound client switches to it: partner calls, card fetches, JWKS fetches, token endpoints, push deliveries and CLI `call`. Injected test clients (`partner_http`) bypass it, which is the documented test seam.
- Tests:
  - `test_rebinding_between_check_and_connect_blocked`: a resolver that answers a public IP first and 169.254.169.254 second. With the guard the connection never reaches the second; without it, it would.
  - `test_sni_hostname_preserved` (a real TLS server with a cert for `localhost`, connected as `localhost`).
  - `test_internal_tier_allows_private`.
  - `test_all_outbound_paths_use_guarded_client`: a structural test that patches the backend and asserts it is called for each path.
- [ ] Steps: fail, implement, pass. Commit with the message `feat(consult): DNS-rebinding-proof outbound connections`.

### Task 9: Signed call contexts between gateways

**Files:**
- Create `src/a2agw/context/signing.py`.
- Modify `serve/executor.py` and `consult/client.py`.
- Tests: `tests/context/test_signing.py`, `tests/integration/test_signed_context.py`.

**Interfaces:**
- Produces:
  - `CallContextSigner(key_path, kid, alg, issuer: str)`, whose `sign(cc) -> str` returns a compact JWS. The payload is `cc.to_metadata()` plus `iss`, `iat`, and `exp = min(cc.deadline, iat + 600)`.
  - `CallContextVerifier(trusted: dict[str, PyJWK])`, whose `verify(token) -> CallContext` raises `CallContextViolation("bad signature")`.
  - Metadata key: `https://a2agw.dev/ext/call-context/v1#jws`.
  - Inbound behaviour:
    - When a valid JWS from a trusted issuer is present, the executor trusts its `path`, `hop` and `origin` instead of the unsigned values. It still clamps to local limits.
    - When a JWS is present but invalid, the call is rejected with "invalid call context".
    - When there is no JWS, Phase 1 behaviour is unchanged.
  - Outbound: when a signer is configured on the host, the client attaches the JWS with `PartnerClient(..., context_signer=None)`.
  - `AgentHost(..., context_signer=None, context_verifier=None)`.
- Tests:
  - Round trip.
  - A tampered hop is rejected.
  - An expired token is rejected.
  - A two-gateway loop A→B→A, where B strips the unsigned path but the JWS is intact, is detected as a cycle by A.
  - An untrusted issuer is ignored when the unsigned values are also present (Phase 1 behaviour).
- [ ] Steps: fail, implement, pass. Commit with the message `feat(context): signed call contexts between gateways`.

### Task 10: Carry-over hardening from the Phase 1 final review

**Files:** `serve/host.py`, `cli.py`, `adapters/langgraph.py`, and tests.

**Decisions:**
- **Signal handler:** wrap `loop.call_soon_threadsafe` in `try/except RuntimeError`. When the previous handler is `None`, or is `SIG_DFL`/`SIG_IGN`, emulate default behaviour by re-raising through `signal.default_int_handler` for SIGINT and doing nothing for the others.
- **Graceful shutdown:** `AgentHost.run()` and `a2agw serve` pass `timeout_graceful_shutdown=10`, and the CLI gains `--graceful-timeout`.
- **LangGraph:** treat a graph with `aget_state` but no local `checkpointer` attribute, such as `RemoteGraph`, as "may have state". In that case, call `aget_state` and propagate its errors.
- **Stream affinity:** add a pinned test, `test_stream_cross_task_affinity`, that reproduces the reviewer's affinity probe (first event in a helper task, then the rest, closed from a third task, over real sockets). It guards the SDK upgrade path.
- **Partner reload:** add `PartnerRegistry.reload()` and an admin `POST /a2agw/admin/partners/reload` (admin scope; audited). A running server can then pick up partners added through the CLI without a restart, which removes the documented Phase 1 limitation.
- Tests for each item.
- [ ] Steps: fail, implement, pass. Commit with the message `fix: carry-over hardening from phase 1 review`.

### Task 11: Boundary-condition and security test matrix

**Files:**
- Create `docs/boundary-conditions.md`, `tests/faults.py` (a fault-injection ASGI middleware), `tests/integration/test_boundaries.py` and `tests/security/test_attack_matrix.py`.

**Decisions:**
- **`FaultInjector(app, plan: dict[str, Fault])`** wraps a partner app. A `Fault` is one of:
  - `latency(s)`
  - `status(code)`
  - `drop_stream_after(n_events)`
  - `malformed_body()`
  - `close_connection()`

  Faults are keyed by JSON-RPC method or REST path.
- **`docs/boundary-conditions.md`** has a table with one row for each of spec §8 items 1–13. Columns: the condition, the expected behaviour, the code that handles it (file:function), and the test ids.
- **Gaps get tests in `test_boundaries.py`.** Every row must name at least one existing or new test.
- **`test_attack_matrix.py`** collects the attacker scenarios in parameterized form:
  - SSRF payloads, the 40-URL list from the Phase 1 review, run against card fetch, the CLI, push and JWKS
  - oversized and too-many parts
  - cycle, hop and budget forgery
  - tampered or unsigned cards
  - authz bypass paths, including root_path
  - prompt-injection card text
  - forged call-context JWS
  - secrets in logs (capture logs during each scenario and assert no secret marker)
- **Done when:** the doc has no empty test cells, and `uv run pytest tests/integration/test_boundaries.py tests/security -q` is green.
- [ ] Steps: write the matrix doc, then the failing tests for the gaps, then fixes (each fix gets a regression test in its own module), then green. Commit with the message `test: boundary-condition and attack matrix`.

### Task 12: Config, CLI, README and conformance wrap-up

**Files:** `config.py`, `cli.py`, `README.md`, `docs/conformance.md`, `examples/software_team` (enable signing and audit in the demo), and tests.

**Decisions:**
- **New `GatewayConfig` sections** (all optional, `extra="forbid"`):
  - `signing: {key_file, kid, alg, jku?}` signs cards, push JWTs and call contexts.
  - `trust: {card_keys: {kid: pem_file}, jwks_urls: [...], require_signed: [tiers], context_issuers: {kid: pem_file}}`.
  - `oauth: {<ref>: {type: client_credentials|token_exchange, token_url, client_id, client_secret_env, scope?, audience?}}`.
  - `tls: {<ref>: {cert_file, key_file, ca_file?}}`. A partner entry gains `tls_ref`.
  - `policy_file`.
  - `push: {allow_private?, timeout_s?, max_retries?}`.
  - `audit: bool` (default true).
  - `server_tls: {cert_file, key_file, ca_file?, require_client_cert?}`.
- **Key files** resolve relative to the config dir. A file that is missing or unreadable raises `ConfigError` naming the file but not its contents.
- **`build_host` wires everything.** `a2agw init` gains `--secure`, which scaffolds a config with signing, a policy file, and auth with a hashed API key, plus a `keys/` dir generated with `cryptography` (Ed25519). Generated keys are created with 0600 permissions and listed in a scaffolded `.gitignore`.
- **README** gains a "Security hardening" section with a worked example for each feature. Phase 2 features move out of the roadmap.
- **Tests:**
  - Config round trips for every section.
  - `init --secure` produces a config that starts and serves a signed card.
  - The demo still passes with signing and audit on.
  - Run the full suite, the TCK and the demo.
- [ ] Commit with the message `feat: phase 2 config, CLI and docs`.

---

## Self-review notes

- **Spec coverage, §9 Phase 2 row:**

  | Requirement | Task |
  |---|---|
  | Signed cards and quarantine | 1 |
  | OAuth2 and mTLS | 2, 3 |
  | Policy engine (authz, egress, routing) | 4, 5 |
  | SSRF guard and DNS-rebinding pinning | 8 |
  | Injection envelope | done in P1, attack-tested in 11 |
  | Push | 6 |
  | Postgres | 7 |
  | Discovery mode | done in P1 |
  | Audit log | 5 |
  | Fault-injection tests | 11 |

- **§11a items:**
  - Item 2, token exchange: Task 2.
  - Item 4, signed contexts: Task 9.
  - Item 6, classification: Tasks 4 and 5.
- **"Done when: security and chaos suites pass and boundary conditions 1–13 covered by tests"** is met by Task 11.
- **Deferred Phase 1 items picked up:**
  - OAuth URL checks: Task 2.
  - DNS pinning: Task 8.
  - Caller identity on cascade: Task 2.
  - Signal handler and RemoteGraph: Task 10.
  - The restart-to-load-partners limitation: Task 10.
