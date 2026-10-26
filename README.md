# a2a-gateway

A framework-agnostic gateway for the [A2A (Agent2Agent) protocol](https://a2a-protocol.org). It works in both directions. **Inbound**, it serves any agent (a plain function, a LangChain runnable, a LangGraph graph) as a standards-compliant A2A server. **Outbound**, it keeps a registry of partner agents, each registered from its Agent Card, and makes them available to your agent as tools (when the agent's code uses `partner_tools`), so the agent's own reasoning decides which partner to consult. It is built on the official `a2a-sdk` and treats every remote party as untrusted by default.

## Features

- One `AgentHost` serves many agents at `/agents/<id>/`, over JSON-RPC and HTTP+JSON, with streaming, cancel, and multi-turn (`input-required`).
- Adapters: plain callables (sync, async, generators), LangChain runnables, and LangGraph graphs (`interrupt()` becomes `input-required`).
- Partner registry with card fetch, pinning, change quarantine, and approval.
- Partner tools with task handles (`ask_<id>`, `a2a_check_task`, `a2a_cancel_task`, `a2a_wait`), and a discovery mode (`find_partners`, `consult_partner`) above 12 partners.
- Resilience on outbound calls: deadline, jittered retries, circuit breaker, per-partner bulkhead.
- Call-context extension: trace, hop budget, deadline, call budget, and re-entry detection across agent networks.
- API-key and JWT auth with per-agent authorization, an SSRF guard, and an untrusted-text envelope for partner output.
- OpenTelemetry tracing, JSON logs, and a read-only admin API with an SSE event stream.
- SQLite or PostgreSQL (`pip install a2a-gateway[postgres]`) task store, with recovery of in-flight tasks on restart. Several gateways can share one PostgreSQL database if each serves different agent ids (one gateway per agent id per database); the audit chain is serialized across them by an advisory lock. SQLite is for a single process.
- Security hardening (all configurable in `a2agw.yaml`): signed Agent Cards (ours signed, partners' verified and quarantined on a key change), OAuth2 client credentials and token exchange, mTLS both ways, a policy engine (authz, egress classification ceilings, routing), a hash-chained audit log, signed call contexts between gateways, and guarded push notifications. See [Security hardening](#security-hardening).
- A CLI: `init [--secure]`, `serve`, `partners`, `card validate`, `call`, `audit export|verify`, `tasks reap`.
- **Conformance:** the inbound side passes the A2A TCK at MUST level. See [docs/conformance.md](docs/conformance.md).

## Install

Requires Python 3.11+.

```bash
uv add a2a-gateway                 # core: callable agents, partners, CLI
uv add "a2a-gateway[langchain]"    # adds the LangChain adapter and tools
uv add "a2a-gateway[langgraph]"    # adds the LangGraph adapter (includes LangChain)
```

`pip install a2a-gateway` works the same way.

## Quickstart (5 minutes)

Scaffold a project, with one echo agent:

```bash
a2agw init myagent
```

```
wrote myagent/a2agw.yaml
wrote myagent/agent.py
wrote myagent/.env.example
```

Start the gateway:

```bash
cd myagent && a2agw serve          # binds 127.0.0.1:8000 by default
```

The scaffold sets `admin_without_auth: true` so you can try the admin API locally. That leaves the admin API open to anyone who can reach the port, so keep the default `--host 127.0.0.1` and configure `auth` (see Configuration) before you bind to `0.0.0.0` with `--host 0.0.0.0`. `a2agw init myagent --secure` scaffolds a hardened project instead: API-key auth, signed cards, a policy and the audit log (see [Security hardening](#security-hardening)).

The echo agent is now served at `http://localhost:8000/agents/echo/`, and its card is at `/agents/echo/.well-known/agent-card.json`. In another terminal (the `partners` commands read `a2agw.yaml`, so stay in `myagent`, or pass `-c myagent/a2agw.yaml`), call it. `call` takes the agent's base URL (the one in its card, with the trailing slash). It treats the target as a `partner` by default, which requires https, so for a local `http://` agent pass `--tier internal`:

```bash
cd myagent
a2agw call http://localhost:8000/agents/echo/ "hello" --tier internal
```

```
state: TASK_STATE_COMPLETED
echo: hello
```

For an agent behind API-key auth, set `A2AGW_API_KEY` in the environment rather than passing `--api-key`: a key on the command line is visible to other users in `ps` and is saved in your shell history. `--api-key` overrides the variable when both are set.

Register an agent as a partner of your gateway. This fetches its card and saves it to `partners.yaml` next to `a2agw.yaml`. Here the agent registers itself, which is enough to see the flow; use another agent's URL in practice:

```bash
a2agw partners add echo http://localhost:8000/agents/echo/ --tier internal
a2agw partners list
```

```
added echo (internal) hash da7686314f77
ID    TIER      STATUS  HASH          PENDING
echo  internal  active  da7686314f77
```

A running `a2agw serve` picks up the new partner after `curl -X POST -H "X-API-Key: $ADMIN_KEY" localhost:8000/a2agw/admin/partners/reload` (admin scope, audited as `partner.reload`; it re-reads `partners.yaml`; an invalid file is a 400 and changes nothing; removing a partner that still has open outbound tasks is a 409 unless `?force=true`), or on its next start. Partners are registered gateway-wide, but an agent only gets them as tools if its code builds them with `partner_tools` / `as_langchain_tools` (see below); the echo agent does not. Open `agent.py` and edit the function: it is a normal Python function.

```python
from a2agw.adapters.callable import agent


@agent(id="echo", description="Echoes the user's message back.")
async def echo(ctx):
    return f"echo: {ctx.text}"
```

## Writing agents

### A callable agent

`@agent` turns a function of `InboundContext` into an `AgentSpec`. The function may return a string, or be a generator yielding strings (streamed as an artifact) and events.

```python
import uvicorn
from a2agw import AgentHost, Done, NeedInput, Status, agent


@agent(id="booker", description="Books a table.")
async def booker(ctx):
    if not ctx.resumed:
        yield NeedInput("For how many people?")  # task becomes input-required
        return
    yield Status("checking availability")
    yield Done(f"Booked a table for {ctx.text}.")


host = AgentHost("http://localhost:8000")
host.add(booker)
uvicorn.run(host.app(), port=8000)
```

`host.run(port=8000)` is a shortcut for the last line. Like uvicorn and `a2agw serve`, it binds `127.0.0.1` by default; pass `host="0.0.0.0"` to accept remote connections, and configure `auth` first. On SIGINT/SIGTERM both wait at most 10 s for open requests before shutting down (`host.run(graceful_timeout_s=...)`, `a2agw serve --graceful-timeout`). After the host stops, the signal handlers that were installed before are restored, with one exception: a handler installed outside Python (`signal.getsignal` returns `None`) cannot be reinstalled, so the gateway's handler stays and a later SIGTERM in the same process is swallowed (SIGINT still raises `KeyboardInterrupt`). If you embed the host and keep the process running afterwards, install your own SIGTERM handler once it has exited.

Events: `Status`, `ArtifactChunk`, `NeedInput`, `NeedAuth`, `Usage`, `Done`, `Failed`, `Reply`.

### A LangGraph agent

`GraphAdapter` runs the graph with `thread_id = contextId`. A LangGraph `interrupt()` ends the turn as `input-required`; the next message on the same task resumes the graph. Use a checkpointer (a persistent one makes `input-required` tasks survive restarts).

```python
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.types import interrupt

from a2agw import AgentHost, AgentSpec, SkillSpec
from a2agw.adapters.langgraph import GraphAdapter


def ask(state: MessagesState):
    answer = interrupt("Which environment?")  # -> input-required
    return {"messages": [("ai", f"Deploying to {answer}")]}


builder = StateGraph(MessagesState)
builder.add_node("ask", ask)
builder.add_edge(START, "ask")
builder.add_edge("ask", END)
graph = builder.compile(checkpointer=InMemorySaver())

deployer = AgentSpec(
    id="deployer",
    name="Deployer",
    description="Deploys a service.",
    skills=[SkillSpec(id="deploy", name="Deploy", description="Deploy a service")],
    adapter=GraphAdapter(graph),
)
host = AgentHost("http://localhost:8000")
host.add(deployer)
```

### An agent that consults partners

`partner_tools(host.partners)` projects the active partners as tools. `as_langchain_tools(tools, host.client)` turns them into LangChain `StructuredTool`s, and each tool returns a JSON string. `host.client` exists once the host has started, so build the tools inside the agent run, as the demo does.

```python
from pathlib import Path

from a2agw import AgentHost, partner_tools
from a2agw.adapters.langchain import as_langchain_tools

host = AgentHost("http://localhost:8000", partners_path=Path("partners.yaml"))


def tools_for_this_run():
    return as_langchain_tools(partner_tools(host.partners), host.client)
```

Give those tools to a tool-calling model, a LangGraph `ToolNode`, or call them directly. A partner call that outlasts `wait_seconds` returns a `working` result with a task handle; poll it with `a2a_check_task` or `a2a_wait`. If a partner needs input, the result has state `input_required` and a `question`; answer by calling the same tool again with that `task_id` and `context_id`. Without LangChain, `a2agw.adapters.callable.as_functions(tools, client)` gives plain async functions.

## Demo

[`examples/software_team`](examples/software_team/README.md) runs three agents built with different frameworks (LangGraph, LangChain, plain Python) from one host. It shows `input-required` across agents, a long task polled through a handle, and one distributed trace. Run it with `uv run python examples/software_team/run_demo.py`.

## Security defaults

- **Trust tiers.** Every partner has a tier: `internal`, `partner`, or `public`. The SSRF guard checks outbound card and endpoint URLs. Outside the `internal` tier, hostnames are resolved and private, loopback, link-local, and metadata addresses are refused. The `internal` tier skips the address checks (cloud metadata addresses excepted), so use it only for agents you operate. See [Security model: outbound connections](#security-model-outbound-connections).
- **https.** Required for every tier except `internal`.
- **Pinned cards and quarantine.** Endpoints come from the card you registered. If a refreshed card changes, the partner is quarantined and its old card stays in force until you approve the new one against its hash:
  ```bash
  a2agw partners verify acme            # reports "unchanged" or "quarantined"
  a2agw partners list                   # shows the PENDING flag and the hash
  a2agw partners approve acme --hash <hash-from-list>
  ```
- **Access control needs `auth`.** Without an `auth` section every caller is anonymous and `AgentAccess` is not enforced, so that setup is for local development only. Once `auth` is set, anonymous callers are always denied on agent endpoints. Agent cards and healthz are public either way, so `allow_anonymous: true` opens nothing extra: it only changes the answer to a request without credentials on an agent route from 401 (unauthenticated) to 403 (forbidden).
- **Principals are prefixed.** `AgentAccess(allowed_principals=...)` takes `key:<principal_id>` for API keys and `jwt:<sub>` for JWTs. An unprefixed id matches nothing.
- **Untrusted partner text.** Text from partners is capped at 64 KiB, and results carry `provenance.untrusted = true`. `UNTRUSTED_NOTE` is appended to the partner tools' descriptions so the model treats partner output as data, not instructions. Binary artifacts are never inlined.
- **Call-context limits.** Every call carries a call context: at most 8 hops by default, an absolute deadline (the default inbound ceiling is 1 hour; it is checked when a call is admitted, not enforced mid-run), an optional call budget (`max_calls`), and the path of agents already involved. A call that comes back to an agent already on its path is rejected unless that agent sets `allow_reentry`. Limits only ever tighten as the context travels. Cancelling an inbound task cancels the partner tasks it started.
- **Inbound limits.** Request bodies up to 10 MiB and 64 parts per message.
- **Admin.** The admin API needs a principal with the `a2agw:admin` scope. With no `auth` configured it is closed, unless you set `admin_without_auth: true` (development only).
- **Secrets.** By design, secrets are kept out of logs, traces, the admin API, and error messages, and credentials are read from the environment at call time. Treat that as the intent, not a guarantee, and review your own agent code and exporters.
- **Library debug logs.** The a2a SDK logs whole request bodies, request headers (including `Authorization`) and events at DEBUG, and aiosqlite logs every SQL statement with its parameters. Importing a2agw therefore sets the `a2a` and `aiosqlite` loggers to INFO, unless your application has already set their level. Root-level DEBUG logging then carries no message text or credentials from them. To see them anyway (never in production), set those loggers to DEBUG explicitly.
- **Inbound limits.** Each part's media type must match the agent's input modes: the union of its skills' `input_modes`, where a skill without its own falls back to `AgentSpec.input_modes`. Wildcards `*/*` and `type/*` are allowed, and an empty list accepts everything. A text part counts as `text/plain` and a data part as `application/json`. A file part counts as its declared media type, or `application/octet-stream` if none is given. A mismatch is `ContentTypeNotSupportedError`. A request re-sent unchanged (same `messageId` and content) by the same principal, in the same tenant, within 24 hours, while its task is still open, does not run the agent again. `SendMessage` returns that task, and a stream resubscribes to it. Once the task has ended, the id starts a new task. All unauthenticated callers count as one principal (`anonymous`), so without `auth`, two anonymous callers that send an identical request under the same `messageId` get the same task.
- **Partner task lifetime.** When an inbound task completes or fails, the partner tasks it left open are cancelled. A partner task still open after `outbound_ttl_s` (default 24 h) is cancelled by the host's maintenance pass, with its handle marked `ttl expired` and an `outbound.expire` audit row.
- **Development switch.** `A2AGW_DEV=1` allows plain `http://` for the `partner` and `public` tiers. It is for local development only; never set it in production.

```python
from a2agw import AgentAccess, AuthConfig

# auth.api_keys holds sha256 hashes of keys, never the keys themselves
access = AgentAccess(
    allowed_principals=frozenset({"key:ci-bot", "jwt:user-42"}),
    required_scopes=frozenset({"deploy"}),
)
# attach it to an agent: @agent(id="deployer", description="...", access=access)
```

### Security model: outbound connections

Every outbound connection the gateway makes itself (partner calls, card and JWKS fetches, the inbound JWT JWKS, OAuth token requests and push webhooks) goes through a guarded client:

- **DNS rebinding.** The client resolves the host itself at connect time, vets every address for the host's tier and connects only to a vetted IP address (TLS still verifies the hostname). A DNS answer that changes after the URL check cannot redirect the connection. When a host has several addresses they are raced (happy eyeballs, 250 ms apart) within one connect timeout. A refused address is permanent: the call is not retried, counts as a circuit-breaker failure and returns `unavailable` ("unsafe partner address"); a push delivery is skipped (`skipped_unsafe`).
- **Cloud metadata.** `169.254.169.254`, `fd00:ec2::254` and `100.100.100.200` are refused on every tier, `internal` included, and with `PushSettings(allow_private=True)`, also when written as IPv4-mapped, NAT64, 6to4 or IPv4-compatible IPv6, or as a decimal/hex IPv4 literal.
- **Proxies are ignored.** A proxy would resolve names itself and defeat the checks, so `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY` do not apply to guarded clients; the host logs one warning at startup when any of them is set. Egress has to be allowed directly (or controlled at the network layer).
- **Logs.** httpx/httpcore do not log the guarded clients' requests (URLs can carry credentials); other clients in your process log as you configure them.
- **The inbound JWT JWKS** is vetted with `auth.jwt.jwks_tier` (default `internal`; set `public` for a hosted IdP to require https and a public address). `jwks_url` must be https (plain http only with `A2AGW_DEV=1`). Keys are cached for 5 minutes; an unknown `kid` refetches at most every 30 s after the last attempt, a failed fetch is not retried for 30 s (requests fail fast with 401 meanwhile), and concurrent requests share one fetch.

## Security hardening

Every feature below is off until configured (except the audit log, which is on by default), and each one is a section of `a2agw.yaml`. Secrets never go in the file itself: key material comes from files (`*_file`, relative to the config file), and other secrets from environment variables named in `*_env` fields. An inline secret-looking key (`client_secret`, `password`, `token`, `private_key`, ...) or a literal password in `db_url` stops startup with a hint to use `*_env` or `${VAR}`. Config errors name the file and the field path, never a value or a file's contents.

### Quick start: `a2agw init --secure`

```bash
a2agw init myagent --secure
```

```
wrote myagent/keys/signing.pem (mode 0600)
wrote myagent/keys/signing.pub.pem (mode 0600)
wrote myagent/a2agw.yaml
...
API key: a2agw_...
WARNING: this API key is shown only once and is not stored anywhere ...
```

This scaffolds a project that signs its cards (a fresh Ed25519 key in `keys/`, mode 0600, directory 0700, listed in the scaffolded `.gitignore`), enforces `policy.yaml`, writes the audit log, and requires auth with one admin API key (principal `key:admin`, scope `a2agw:admin`). Only the key's sha256 hash goes into `a2agw.yaml`; the key itself is printed once and never written to disk. Existing key files are never overwritten, not even with `--force`. Publish `keys/signing.pub.pem` (and the `kid` from `a2agw.yaml`) to partners that should verify your cards.

### Signed Agent Cards

```yaml
signing:                         # our key: signs our cards, push JWTs and call contexts
  key_file: keys/signing.pem     # PEM: Ed25519, EC P-256 or RSA >= 2048; unencrypted
  kid: gw-2026-10
  alg: EdDSA                     # EdDSA | ES256 | RS256 (must match the key)
  jku: https://gw.example.com/jwks.json   # optional: where partners fetch our keys
  # issuer: https://gw.example.com       # call-context issuer; default base_url

trust:                           # partner cards and partner call contexts
  card_keys:                     # pinned partner keys: kid -> PEM public key file
    acme-1: keys/acme.pub.pem
  jwks_urls:                     # allowlisted jku URLs (fetched SSRF-guarded, public tier)
    - https://agents.acme.example/.well-known/jwks.json
  require_signed: [partner, public]   # tiers whose cards must carry a valid signature
```

Every card the host serves (per agent and the root card) is signed with JWS over the RFC 8785 canonical card. A partner card is verified on registration and on every refresh against the pinned keys or an allowlisted `jku`; only ES256, RS256 and EdDSA are accepted (`alg: none` and HS256 are refused). On a `require_signed` tier an unsigned, tampered or untrusted card is refused. A refreshed card signed by a different key, or with a signature that no longer verifies, is quarantined like any other significant change until you `a2agw partners approve` its hash. The `partners` commands use the same `trust` and `tls` settings as `serve`.

### Signed call contexts

With `signing` set, every outbound consult also carries a JWS of its call context (hop count, path, deadline, budget), and the host trusts its own key, so a call that loops back through other gateways is still recognised as a cycle. To trust other gateways' contexts:

```yaml
trust:
  context_issuers:               # kid -> issuer and public key
    peer-gw-1: {issuer: https://peer.example.com, key_file: keys/peer.pub.pem}
```

With `signing` or `context_issuers` set, an inbound call with a context JWS that does not verify is rejected ("invalid call context"); without either, the JWS is ignored. A call without one is admitted on its unsigned context as before, clamped to local limits.

### OAuth2 to partners

```yaml
oauth:                           # each key is a credential_ref
  acme:                          # one gateway token for every partner with credential_ref: acme
    type: client_credentials
    token_url: https://login.acme.example/oauth/token
    client_id: my-gateway
    client_secret_env: ACME_CLIENT_SECRET   # the env var holding the secret
    scope: a2a                   # optional
    audience: https://agents.acme.example   # optional
  acme-obo:                      # RFC 8693: exchange the inbound caller's JWT per call
    type: token_exchange
    token_url: https://login.acme.example/oauth/token
    client_id: my-gateway
    client_secret_env: ACME_CLIENT_SECRET
    audience: https://agents.acme.example   # required
    fallback: acme               # client_credentials token for maintenance calls (cascade cancels, recovery)

partners:
  - {id: acme, url: "https://agents.acme.example/agents/support/", tier: partner, credential_ref: acme-obo}
```

A credential ref is either a static `credentials` entry or an `oauth` entry, never both. Token requests go through the SSRF-guarded client (public tier, https). Tokens are cached until shortly before expiry; a partner's 401 before it accepts a send drops the token and resends once with a fresh one. A token exchange needs an inbound JWT: when the caller authenticated with an API key (or there is no inbound call), the consult fails with "credential error" and nothing is sent.

### mTLS

```yaml
tls:                             # outbound client certificates, by tls_ref
  acme: {cert_file: tls/client.crt, key_file: tls/client.key, ca_file: tls/acme-ca.crt}
partners:
  - {id: acme, url: "https://agents.acme.example/", tier: partner, tls_ref: acme}

server_tls:                      # inbound HTTPS for `a2agw serve`
  cert_file: tls/server.crt
  key_file: tls/server.key
  ca_file: tls/clients-ca.crt    # needed with require_client_cert
  require_client_cert: true
```

One mapping built from `tls:` is shared by the registry (card fetches) and the partner client (calls); a partner with `tls_ref` then uses a dedicated TLS 1.2+ client that presents that certificate and trusts `ca_file`. An unknown `tls_ref` is a config error (and, for records added otherwise, fails closed at call time: `unavailable`, "tls config missing"). `a2agw partners add ... --tls-ref acme` registers a partner over mTLS. In code: `AgentHost(tls={"acme": TlsClientConfig(cert_file, key_file, ca_file)})`.

Inbound: `server_tls`, or the flags `a2agw serve --ssl-certfile F --ssl-keyfile F [--ssl-ca-certs F --require-client-cert]` (the flags win), or `AgentHost.run(ssl_*=...)`. The client certificate is verified at the TLS layer only; ASGI servers do not expose it, so identity still comes from the API key or JWT. Certificates are loaded at startup; rotating them requires a restart. Passphrase-protected keys are refused, and a group- or world-readable key file logs a warning.

Troubleshooting: when a partner rejects our client certificate under TLS 1.3, the result can show "delivery unknown" instead of "partner unreachable", because the platform reports a plain connection reset. The gateway deliberately never resends in that case.

### Policy and audit

In `a2agw.yaml`: `policy_file: policy.yaml` (validated at startup; any error stops it, naming the file and field path), optionally `classifier: regex_pii` (flags common PII as `confidential`), and `audit: true` (the default; `false` turns the log off). In code: pass `AgentHost(..., policy=PolicyEngine(load_policy(path)))`. The policy is declarative (see `a2agw.security.policy` for the file format) and applies in three places:

- **Authz.** Every agent request except the card is checked after `AgentAccess`; both must allow. A denial is a bare `403 {"error": "forbidden"}`; the reason goes only to the audit log. The policy also applies when no `auth` is configured: every caller is then `anonymous`, which a `principal: "*"` allow rule never matches, so a no-auth development setup needs an explicit `{principal: "anonymous", agents: [...], effect: allow}` rule.
  - *A lone deny rule is a lockdown, not a blocklist.* As soon as any rule mentions an agent, callers without a matching allow rule are denied ("default deny"). `{principal: "key:mallory", agents: [billing], effect: deny}` on its own denies everyone on `billing`; add `{principal: "*", agents: [billing], effect: allow}` to deny only mallory.
  - *Deny rules match conservatively when the skill is unknown.* Requests are checked with no skill id (there is no skill routing yet), so a deny rule matches whatever its `skills` list says, while an allow rule matches only with `skills: "*"`.
- **Egress.** `PartnerClient.consult(..., classification=...)` (and the `classification` argument of the `ask_*` tools) labels outbound data `public`, `internal`, `confidential` or `restricted`. Labels only ever raise the level, never lower it: the effective level is the highest of the explicit label (if given), the calling agent's `defaults.agent_classification` (or, if the agent has none, `defaults.unknown_classification`) and the optional classifier's result. So a label chosen by an LLM through a tool argument can never take data below the operator's floor. The classifier sees the message text and `data`, not file attachments. It must not exceed the partner's ceiling: `egress.partner_ceilings[id]`, else `egress.tier_ceilings[tier]` (defaults: internal=restricted, partner=confidential, public=public). A call above the ceiling returns `rejected` ("egress policy: ...") and sends nothing. The calling agent is the one whose adapter is running; outside an inbound run (e.g. a direct `host.client.consult(...)` from your own code) it is the client's `agent_id`, `"host"` for the host's client.
- **Routing.** `host.partner_tools(agent_id)` (or `partner_tools(registry, policy=..., agent_id=...)`) hides `forbid`den partners, lists `prefer`red ones first and marks forced and preferred ones "Required for this agent." / "Preferred.". A routing evaluation error offers no partner tools at all (fail closed). Routing rules that name unknown partner ids are logged once at startup. Routing only shapes the tool list the LLM is offered (what it sees and is nudged towards); it is not an enforcement boundary. Code that calls `PartnerClient.consult` directly bypasses it, so the enforcement boundary is authz plus the egress ceilings.

Any policy evaluation error denies.

**Audit log.** By default (`AgentHost(audit=True)`) the gateway appends to a hash-chained table `a2agw_audit` in its database: inbound admissions and rejections, authz denials, partner calls (outcome = result state), egress denials, partner registry changes and admin reads. Each row holds ids, the action, the outcome, a classification and a short allowlisted `detail` (reason, rule, state, tier, ...). It never stores message text, data, artifact contents or secrets. Each row's hash covers the previous row's hash, so editing or deleting a row breaks the chain (removing the newest rows is only detectable against an exported copy). The chain is tamper-evident, not tamper-proof: someone with write access to the database can rewrite rows and recompute every later hash. Exported copies kept elsewhere (and their last hash) are the anchor to compare against.

```bash
curl -H "X-API-Key: $ADMIN_KEY" "localhost:8000/a2agw/admin/audit?action=egress.deny&limit=50"
curl -H "X-API-Key: $ADMIN_KEY" localhost:8000/a2agw/admin/audit/verify   # {"ok": true}
a2agw audit export -c a2agw.yaml --since 2026-10-01T00:00:00Z > audit.jsonl
a2agw audit verify -c a2agw.yaml                                          # exit 1 if broken
```

The audit log is fail-open for availability: a failed append is logged and counted in `audit_errors` (shown by `/a2agw/admin/healthz`), and the request goes on. Every event is its own committed transaction, so each audited request pays one extra commit (on sqlite in WAL mode, the default here, that is one fsync per event); waiting for the audit lock is capped at 5 s (up to about twice that on PostgreSQL, where there is also a cross-process lock), after which the event is counted as an audit error rather than blocking the request. Denials of anonymous callers are coalesced to one row per agent (or admin category) per 60 s, with `detail.count` holding the number suppressed; authenticated denials are recorded one by one. On PostgreSQL, gateways sharing a database append to one chain, serialized by an advisory lock (waiting is capped like the in-process lock); on SQLite assume a single writer process. Run one gateway per agent id per database: if an agent is moved or removed, the host logs how many open tasks belong to agents it does not serve, and `a2agw tasks reap --agent <id> -c a2agw.yaml` (or `POST /a2agw/admin/tasks/reap?agent=<id>`, admin scope, audited as `task.reap`) fails those tasks and cancels their partner tasks. Reaping is guarded: without `--yes` (CLI) or `confirm=true` (admin) it is a dry run that only counts the tasks and partner tasks it would touch; tasks changed in the last 10 minutes are refused (HTTP 409) unless `--force` / `force=true`; an agent the gateway serves is always refused; every attempt is audited as `task.reap`. `AgentHost(audit=False)` turns the audit log off.

### Push notifications

```yaml
push:                            # omit to not offer push (the card then says so)
  allow_private: false           # true: also private/loopback and plain-http webhooks (internal tier)
  timeout_s: 10                  # per request and per delivery-time URL re-check
  max_attempts: 3                # attempts per delivery in total (1 = no retry)
  encryption_key_env: PUSH_KEYS  # Fernet key(s), comma-separated; encrypts stored configs
  max_configs_per_task: 10
  max_concurrent_deliveries: 32  # POSTs in flight per agent (one task gets at most half)
  max_pending_tasks: 1000        # tasks with queued updates per agent; beyond it updates are dropped
```

Webhook URLs are checked when a config is created and again before every delivery (SSRF guard, connect-time address pinning, no redirects). 5xx and connect errors are retried with jittered backoff; 4xx is final. Each request carries `X-A2AGW-Delivery-Id` (the same on every retry: de-duplicate on it), the config's `token` as `X-A2A-Notification-Token`, and its `authentication` credentials as `Authorization`. With `signing` set, each request also carries a short-lived JWT signed with the gateway key (claims `iss`, `aud` = the webhook URL, `exp`, `task_id`, `delivery_id`, `body_sha256`, `jti`). It goes in `Authorization: Bearer` when the config has no `authentication` credentials; when the config's own credentials take the `Authorization` header, the gateway JWT moves to `X-A2AGW-Push-JWT`. Delivery counters (delivered, failed, retries, skipped_unsafe, dropped, pending) are at `GET /a2agw/admin/push`. Without `auth`, every caller is the same `anonymous` owner of push configs, so run with auth whenever push is exposed beyond a trusted network.

### PostgreSQL

```yaml
db_url: postgresql+asyncpg://gw:${GW_DB_PASSWORD}@db.internal:5432/gw   # needs a2a-gateway[postgres]
```

Write the password as `${VAR}` (or the whole URL as `${DB_URL}`): a literal password in `db_url` is refused. The CLI turns database failures (bad URL, connection refused, authentication failed) into one line on stderr with the URL's userinfo shown as `***@`, and `a2agw serve` checks the database before it starts listening.

## Observability

```python
from a2agw import setup_telemetry

setup_telemetry("my-gateway")  # JSON logs plus an OpenTelemetry tracer provider
```

Or set `telemetry:` in `a2agw.yaml`. Two span names are emitted: `a2agw.inbound` for each inbound task and `a2agw.partner_call` for each outbound call. The trace context travels between agents in the call-context extension (`https://a2agw.dev/ext/call-context/v1`), so one request is one trace across the whole network. Spans carry identifiers and states, never message text or credentials. To export over OTLP, pass your own exporter to `setup_telemetry(exporter=...)`, or set `telemetry.otlp_endpoint` (needs `opentelemetry-exporter-otlp`).

The read-only admin API is mounted on the host:

| Endpoint | Returns |
|---|---|
| `GET /a2agw/admin/healthz` | Liveness (no auth) |
| `GET /a2agw/admin/agents` | Hosted agents and their skills |
| `GET /a2agw/admin/partners` | Partners with tier, status, card hash, breaker state, in-flight calls |
| `GET /a2agw/admin/tasks` | Task index; filters `agent`, `state`, `limit`, `cursor` |
| `GET /a2agw/admin/events` | Server-sent event stream (`task.state`, `partner.call`) |
| `POST /a2agw/admin/partners/reload` | Re-reads the partners file; returns the ids added, updated and removed (`force=true` to remove partners with open outbound tasks) |

## Configuration

`a2agw.yaml` is read by `a2agw serve`, the `partners` commands, `audit` and `tasks reap`. `${VAR}` and `${VAR:-default}` are replaced from the environment in string values only, after the YAML is parsed, so an environment value can never add structure (use `$$` for a literal `$`). Unknown fields are rejected at every level, and so are wrong types; the error names the field path (`push.timeout_s: Input should be a valid number`) and never the value. Secrets are never inline: use `*_env` fields, `*_file` fields (relative to the config file) or `${VAR}`; see [Security hardening](#security-hardening) for the Phase 2 sections (`signing`, `trust`, `oauth`, `tls`, `server_tls`, `policy_file`, `classifier`, `push`, `audit`).

```yaml
base_url: ${A2AGW_BASE_URL:-http://localhost:8000}   # public URL, used in agent cards
db_url: sqlite+aiosqlite:///a2agw.db                 # task store
partners_file: partners.yaml                         # partner registry, relative to this file
admin_without_auth: false                            # true = open admin API (development only)
outbound_ttl_s: 86400                                # cancel partner tasks still open after this (s)
audit: true                                          # hash-chained audit log (default true)

auth:                                                # omit for no authentication
  allow_anonymous: false                             # true: no-credential agent calls get 403, not 401
  api_keys:                                          # key: sha256 hex of the API key
    "<64-char sha256 hex>":
      principal_id: ci-bot                           # becomes key:ci-bot
      scopes: [a2agw:admin, deploy]
  jwt:
    issuer: https://login.example.com
    audience: a2agw
    jwks_url: https://login.example.com/.well-known/jwks.json   # or public_key_pem: |
                                                     # https only; http only with A2AGW_DEV=1
    jwks_tier: public                                # SSRF tier for the JWKS host (default internal)
    scopes_claim: scope

agents:                                              # module:attribute, importable from this dir
  - spec: agent:echo                                 # an AgentSpec, or a zero-argument factory

partners:                                            # registered at startup if not present
  - id: acme
    url: https://agents.acme.example/agents/support/ # or card_file: cards/acme.json
    tier: partner                                    # internal | partner | public
    credential_ref: acme                             # a credentials or oauth entry
    tls_ref: acme                                    # optional: a tls entry (mTLS)
    tags: [support]

credentials:                                         # credential_ref -> header filled from env
  acme:
    header: Authorization
    env: ACME_TOKEN                                  # the env var holds the full header value

telemetry:
  service_name: my-gateway
  otlp_endpoint: ${OTLP_ENDPOINT:-}                  # optional

# Phase 2 sections, each optional (worked examples under Security hardening):
# signing: {key_file, kid, alg, jku?, issuer?}
# trust: {card_keys: {kid: pem_file}, jwks_urls: [...], require_signed: [tiers],
#         context_issuers: {kid: {issuer, key_file}}}
# oauth: {<credential_ref>: {type: client_credentials | token_exchange, token_url, client_id,
#         client_secret_env, scope?, audience?, fallback?}}
# tls: {<tls_ref>: {cert_file, key_file, ca_file?}}
# server_tls: {cert_file, key_file, ca_file?, require_client_cert?}
# policy_file: policy.yaml
# classifier: regex_pii                              # needs policy_file
# push: {allow_private?, timeout_s?, max_attempts?, encryption_key_env?, max_configs_per_task?,
#        max_concurrent_deliveries?, max_pending_tasks?}
```

Generate an API-key hash with `printf %s "$KEY" | shasum -a 256 | cut -d' ' -f1` (in Python: `a2agw.security.auth.hash_api_key(key)`), or let `a2agw init --secure` generate a key and its hash.

When auth is not configured, every caller is the same principal, `anonymous`: idempotent re-sends (same `messageId` and request) and push config ownership are then shared by all anonymous callers. The `a2a` and `aiosqlite` loggers default to INFO (see Security defaults).

## Architecture

```
                 +------------------- a2agw ---------------------+
   inbound A2A   |  Serve: card, JSON-RPC + REST, auth, task     |
  ─────────────▶ |  store, executor ──▶ adapter ──▶ your agent   |
                 |                      (callable / LangChain /  |
                 |                       LangGraph)              |
                 |                           │ partner tools     |
   outbound A2A  |  Consult: registry, PartnerClient             |
  ◀───────────── |  (deadline, retry, breaker, SSRF guard)       |
                 |                                               |
                 |  Cross-cutting: call context, OpenTelemetry,  |
                 |  event bus, admin API                         |
                 +-----------------------------------------------+
```

The core never imports a framework; adapters live in `a2agw.adapters.<name>` behind extras. See the [design spec](docs/superpowers/specs/2026-10-25-a2a-gateway-framework-design.md), the [Phase 1 plan](docs/superpowers/plans/2026-10-25-phase1-core.md) and the [Phase 2 plan](docs/superpowers/plans/2026-10-26-phase2-hardening.md).

## Roadmap

Phase 1 (the core) and Phase 2 (hardening: signed cards and quarantine, OAuth2 client credentials and token exchange, mTLS, the policy engine with classification, the audit log, push notifications, PostgreSQL, the SSRF guard with DNS-rebinding pinning, signed call contexts, and the boundary/attack test matrix in [docs/boundary-conditions.md](docs/boundary-conditions.md)) are implemented and described above. Everything below is planned and not implemented yet.

- **Phase 3, gateway:** a sidecar service for agents in any language, an MCP gateway, adapters for CrewAI, OpenAI Agents, Claude Agent SDK, ADK, AG2 and LlamaIndex, and a Docker image.
- **Phase 4, control plane:** a central registry, and the Console (a web UI to register and approve partners, edit policy, and inspect cross-agent traces), with SSO and RBAC.
- **Phase 5, clusters and projects:** agent teams (Clusters) with an orchestrator, a project board, and human-in-the-loop in the Console.

gRPC is not offered today.

## License

Apache-2.0. See [LICENSE](LICENSE).
