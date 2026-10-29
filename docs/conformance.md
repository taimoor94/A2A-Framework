# A2A conformance

a2agw's inbound side is checked with the official A2A Technology Compatibility Kit,
[a2aproject/a2a-tck](https://github.com/a2aproject/a2a-tck).

| | |
|---|---|
| TCK version | `1.0.0` (`git describe`: `1.0.0.alpha3-2-gd4d6fae`) |
| TCK commit | `d4d6fae7887f88ef607fb461c13e3b0e1802f19b` (2026-10-22) |
| Spec tested | A2A 1.0 (the TCK's `specification/`, A2A commit `1736957`) |
| a2a-sdk | 1.2.3 |
| Date | 2026-10-29 (re-run after Phase 3; earlier runs 2026-10-26 and 2026-10-25) |
| Transports | JSON-RPC, HTTP+JSON (a2agw does not serve gRPC) |
| SUT | `examples/tck_sut/sut_agent.py`: one `AgentSpec` + `CallableAdapter` on `AgentHost`, port 9999, no auth, push notifications on (`PushSettings(allow_private=True)`) |

## Results

### MUST: passing

| | passed | failed | skipped |
|---|---|---|---|
| tests | 155 | 0 | 80 |
| requirements | 82 | 0 | 11 skipped, 21 not tested |

Re-run on 2026-10-29 at the end of Phase 3 (sidecar webhook and stdio agents, the outbound
REST API and MCP server, six framework adapters, the Docker image): `scripts/run_tck.sh`
exits 0 with the same numbers, 155 passed, 0 failed, 80 skipped (30 deselected as non-MUST),
MUST compatibility 82 of 114 requirements passing, 0 failing, 11 skipped, 21 not tested
(79.6%). The SUT is unchanged; the sidecar routes (`/a2agw/v1`, `/a2agw/mcp`) are outside
the A2A surface the TCK tests, and the MCP server is off unless configured.

Re-run on 2026-10-26 at the end of Phase 2 (signed cards, OAuth2, mTLS, policy, audit, push,
PostgreSQL, guarded network, signed call contexts): `scripts/run_tck.sh` exits 0 with the same
numbers, 155 passed, 0 failed, 80 skipped (30 deselected as non-MUST), MUST compatibility 82 of
114 requirements passing, none failing. The SUT runs with its defaults (no auth, no signing);
the Phase 2 features are off unless configured, and the audit log, which is on, does not
change protocol behaviour.

All ten push requirements (`PUSH-CREATE-001/002`, `PUSH-GET-001/002`, `PUSH-LIST-001`, `PUSH-DEL-001/002`, `PUSH-DELIVER-001/002/003`) now run and pass on JSON-RPC and HTTP+JSON. The SUT turns push on with `allow_private=True` because the TCK's webhook receiver listens on `http://localhost`; the `AgentHost` default (`allow_private=False`) accepts only public https webhooks.

Why tests are skipped. All of these are TCK skips, not failures:

- 61: the gRPC transport is not offered (this now includes the gRPC variants of the push tests).
- 6: the card does not declare an extended agent card.
- 5: tests that only apply when push notifications are unsupported (`PushNotificationNotSupportedError`, -32003).
- 4: tests that only apply when streaming is unsupported.
- 2: the card declares no required extension.
- 2: wrong-`Content-Type` probes, including `HTTP_JSON-STATUS-001` (415). The SDK accepts the request, and the TCK skips rather than fails in that case.

"Not tested" means requirements this TCK has no automated test for: card signing, auth, TLS, versioning and binding equivalence.

### SHOULD (for information)

13 passed, 0 failed, 7 skipped (unchanged with push on: the TCK has no SHOULD-level push tests).

- `CARD-CACHE-001` passes now. `AgentHost(card_cache_control=...)` defaults to `public, max-age=300` on every card route; pass `None` to omit the header.
- Skips: 4 are for gRPC, which is not offered, and 3 are "No requirements at this level".

### MAY (for information)

6 passed, 1 failed, 3 skipped.

- `CARD-CACHE-003`, `test_last_modified_present`: the agent card response has no `Last-Modified` header. The SDK's card route does not set it.
- Skips: all 3 are for gRPC, which is not offered.

## Known limitations

- **A2A 0.3 streaming error codes.** Inbound 0.3 requests are served by the SDK's 0.3
  compatibility adapter (`enable_v0_3_compat`). On a 0.3 streaming call
  (`message/stream`, `tasks/resubscribe`), every error raised once the stream has started is
  sent as a JSON-RPC `InternalError` (-32603) with the error's message, instead of its
  specific code (for example -32001 `TaskNotFoundError`): the SDK's
  `JSONRPC03Adapter` maps every exception in the stream generator to -32603. 1.0 requests,
  and 0.3 non-streaming calls, get the specific codes. The TCK tests A2A 1.0 only, so this
  does not show in its results.
- **Not covered by the TCK.** Card signing, auth, TLS, versioning and binding equivalence
  (the 21 "not tested" MUST requirements) have no automated TCK test. a2agw's own suite
  covers its implementation of signing, auth, mTLS and version negotiation
  (`tests/security`, `tests/consult/test_tls.py`, `tests/integration/test_boundaries.py`).

## Gaps the TCK found, and what was fixed

| TCK requirement | Gap | Fix |
|---|---|---|
| `DM-MSG-001` (MUST) | An adapter could not answer with a bare `Message`; every turn created a Task. | New adapter event `a2agw.core.events.Reply(text)` and opt-in `AgentSpec.direct_replies`. When the flag is on, the Task is created lazily, at the adapter's first non-`Reply` event, and a first `Reply` returns a Message with no task. Without the flag, a `Reply` completes the task with the text as its status message. A pending direct-reply turn is indexed as SUBMITTED from admission, so re-entry detection and the cancellation cascade cover it. A direct `Reply` deletes that index row, cancels any partner tasks the turn started, and publishes `task.state` = `DIRECT_REPLY` on the bus. |
| `CARD-CACHE-001` (SHOULD) | The agent card had no `Cache-Control` header. | `AgentHost(card_cache_control="public, max-age=300")`, passed to both card routes. |
| `CORE-CANCEL-002` on HTTP+JSON (MUST) | The SDK returns 400 for `TaskNotCancelableError`, but spec §5.4 requires 409. | `AgentHost` wraps each agent's routes in `_RestConformance`, which remaps REST error statuses by `ErrorInfo.reason` to match §5.4: `TASK_NOT_CANCELABLE` to 409, `CONTENT_TYPE_NOT_SUPPORTED` to 415, `INVALID_AGENT_RESPONSE` to 502. The body's `code` is updated too. SDK clients map errors by reason, so they are unaffected. |
| `HTTP_JSON-SVC-001` (MUST) | The SDK labels REST responses `application/a2a+json`, but spec §11.1 and the TCK require `application/json`. | The same wrapper rewrites the header to `application/json`. |
| `PUSH-*` (MUST; they were skipped) | Push notifications were not offered. | `AgentHost(push=PushSettings(...))` (`a2agw.serve.push`): per-agent config stores, owner-scoped CRUD through the SDK handler, and a sender that re-checks the webhook URL with netguard on every delivery, never follows redirects, retries 5xx and connect errors with jittered backoff, and delivers in the background in order per task. The config's `authentication` is sent as `Authorization` (`PUSH-DELIVER-001`) and its `token` as `X-A2A-Notification-Token`. |
| History tests (`CORE-HIST-*`, SHOULD; they were skipped) | A follow-up that sends only `taskId` gets a fresh `contextId` from the SDK, so the task's events failed with "Context in event doesn't match TaskManager". | `AdapterExecutor` uses the existing task's `context_id`. |

Each fix has a regression test, in `tests/serve/test_executor.py`, `tests/serve/test_host.py` and `tests/serve/test_push.py`.

The TCK reads the root card at `/.well-known/agent-card.json` and then calls the interface URLs that card advertises (`/agents/tck/` and `/agents/tck/rest`). No root-path mount was needed.

## Reproducing

Prerequisites: `uv`, `git`, `curl`, network access for the first clone, and Python 3.11 or newer.

From the repo root:

```bash
scripts/run_tck.sh                     # MUST level; exits nonzero if any MUST test fails
TCK_LEVEL=should scripts/run_tck.sh    # SHOULD level, for information
TCK_LEVEL=may scripts/run_tck.sh       # MAY level, for information
scripts/run_tck.sh -- -k cancel -v     # extra pytest arguments are passed to the TCK
```

The script does the following:

1. Clones the TCK into `.tck/a2a-tck`, which is git-ignored, and checks out the pinned commit.
2. Creates the TCK's own virtualenv there, and reinstalls the TCK into it whenever the pinned commit changes. None of its dependencies enter this project.
3. Starts the SUT in the background, logging to `.tck/sut.log`, and waits for `/.well-known/agent-card.json`.
4. Runs `run_tck.py --sut-host http://localhost:9999 --level <level>`.
5. Stops the SUT on exit: SIGTERM, then SIGKILL after 10 s. Ctrl-C exits with status 130.

Reports are written to `.tck/a2a-tck/reports/`: `compatibility.json`, `compatibility.html`, `tck_report.html` and `junitreport.xml`.

The TCK is not part of `uv run pytest`, because it needs a live server. `tests/integration/test_tck_sut.py` runs the SUT in-process and checks one completed task and one direct message, so the SUT keeps working between TCK runs.

To move to a newer TCK, update `TCK_SHA` in `scripts/run_tck.sh` and in this file. Then regenerate the reference SUT (`make codegen-a2a-python-sut` in `.tck/a2a-tck`) and compare its behaviours with `examples/tck_sut/sut_agent.py`.
