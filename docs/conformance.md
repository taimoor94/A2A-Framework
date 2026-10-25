# A2A conformance

a2agw's inbound side is checked with the official A2A Technology Compatibility Kit,
[a2aproject/a2a-tck](https://github.com/a2aproject/a2a-tck).

| | |
|---|---|
| TCK version | `1.0.0` (`git describe`: `1.0.0.alpha3-2-gd4d6fae`) |
| TCK commit | `d4d6fae7887f88ef607fb461c13e3b0e1802f19b` (2026-10-22) |
| Spec tested | A2A 1.0 (the TCK's `specification/`, A2A commit `1736957`) |
| a2a-sdk | 1.2.3 |
| Date | 2026-10-25 |
| Transports | JSON-RPC, HTTP+JSON (a2agw does not serve gRPC) |
| SUT | `examples/tck_sut/sut_agent.py`: one `AgentSpec` + `CallableAdapter` on `AgentHost`, port 9999, no auth |

## Results

### MUST: passing

| | passed | failed | skipped |
|---|---|---|---|
| tests | 139 | 0 | 96 |
| requirements | 73 | 0 | 20 skipped, 21 not tested |

Why tests are skipped. All of these are TCK skips, not failures:

- 52: the gRPC transport is not offered.
- 30: push notifications are not supported. The card declares `pushNotifications: false`.
- 6: the card does not declare an extended agent card.
- 2: the card declares no required extension.
- 4: tests that only apply when streaming is unsupported.
- 2: wrong-`Content-Type` probes, including `HTTP_JSON-STATUS-001` (415). The SDK accepts the request, and the TCK skips rather than fails in that case.

"Not tested" means requirements this TCK has no automated test for: card signing, auth, TLS, versioning and binding equivalence.

### SHOULD (for information)

13 passed, 0 failed, 7 skipped.

- `CARD-CACHE-001` passes now. `AgentHost(card_cache_control=...)` defaults to `public, max-age=300` on every card route; pass `None` to omit the header.
- Skips: 4 are for gRPC, which is not offered, and 3 are "No requirements at this level".

### MAY (for information)

6 passed, 1 failed, 3 skipped.

- `CARD-CACHE-003`, `test_last_modified_present`: the agent card response has no `Last-Modified` header. The SDK's card route does not set it.
- Skips: all 3 are for gRPC, which is not offered.

## Gaps the TCK found, and what was fixed

| TCK requirement | Gap | Fix |
|---|---|---|
| `DM-MSG-001` (MUST) | An adapter could not answer with a bare `Message`; every turn created a Task. | New adapter event `a2agw.core.events.Reply(text)` and opt-in `AgentSpec.direct_replies`. When the flag is on, the Task is created lazily, at the adapter's first non-`Reply` event, and a first `Reply` returns a Message with no task. Without the flag, a `Reply` completes the task with the text as its status message. A pending direct-reply turn is indexed as SUBMITTED from admission, so re-entry detection and the cancellation cascade cover it. A direct `Reply` deletes that index row, cancels any partner tasks the turn started, and publishes `task.state` = `DIRECT_REPLY` on the bus. |
| `CARD-CACHE-001` (SHOULD) | The agent card had no `Cache-Control` header. | `AgentHost(card_cache_control="public, max-age=300")`, passed to both card routes. |
| `CORE-CANCEL-002` on HTTP+JSON (MUST) | The SDK returns 400 for `TaskNotCancelableError`, but spec §5.4 requires 409. | `AgentHost` wraps each agent's routes in `_RestConformance`, which remaps REST error statuses by `ErrorInfo.reason` to match §5.4: `TASK_NOT_CANCELABLE` to 409, `CONTENT_TYPE_NOT_SUPPORTED` to 415, `INVALID_AGENT_RESPONSE` to 502. The body's `code` is updated too. SDK clients map errors by reason, so they are unaffected. |
| `HTTP_JSON-SVC-001` (MUST) | The SDK labels REST responses `application/a2a+json`, but spec §11.1 and the TCK require `application/json`. | The same wrapper rewrites the header to `application/json`. |
| History tests (`CORE-HIST-*`, SHOULD; they were skipped) | A follow-up that sends only `taskId` gets a fresh `contextId` from the SDK, so the task's events failed with "Context in event doesn't match TaskManager". | `AdapterExecutor` uses the existing task's `context_id`. |

Each fix has a regression test, in `tests/serve/test_executor.py` and `tests/serve/test_host.py`.

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
