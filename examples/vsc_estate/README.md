# The demo estate

A small but real three-repository system for Verified System Change (VSC), and the first
proof corpus for it: ten engineering scenarios, each with acceptance tests that fail on the
estate as it is and pass once the change is made.

| Repository          | What it is                                                                                         | Gate                       | Tests                                   |
| ------------------- | -------------------------------------------------------------------------------------------------- | -------------------------- | --------------------------------------- |
| `orders-api`        | Python, Starlette + SQLite. Customer orders; every order line reserves stock in inventory over HTTP | `python -m py_compile app.py` | `python -m pytest -q tests` (inventory faked with `httpx.MockTransport`) |
| `inventory-service` | Node 24, standard library only. Product catalogue, stock, reserve and release                     | `node --check server.mjs`  | `node --test "test/*.test.mjs"`         |
| `contract`          | `openapi/orders.yaml`, `openapi/inventory.yaml`, and the cross-service suite                        |                            | `python -m pytest -q tests`             |

The contract suite (`contract/tests/`) starts both real services as subprocesses on free
ports, waits for `/healthz`, exercises the cross-service flows (place, reserve, refuse,
cancel) and checks every response against the OpenAPI documents (status documented, body
matching the schema, `additionalProperties: false` enforced), then stops the services. It
finds the service repositories through `VSC_WS_ORDERS_API` and `VSC_WS_INVENTORY_SERVICE`
(set by the gateway's whole-system check) or, when those are unset, as sibling directories.

No dependency beyond what this repository already has: Starlette, uvicorn, httpx, PyYAML and
pytest on the Python side, Node 24 on the other.

## Try it

```sh
uv run python examples/vsc_estate/init_estate.py examples/vsc_estate/estate
cd examples/vsc_estate/estate/contract && uv run python -m pytest -q tests
```

`init_estate.py <target>` copies the three directories into `<target>/` and makes each a git
repository on `main` with one commit (local `user.name`/`user.email`). It refuses a target
that exists and is not empty. `a2agw.yaml` in this directory is the estate's gateway config:
three systems pointing at `./estate/<id>`, one whole-system check `estate`, the scripted
planner, and no workers (add yours before running a job).

The `estate` check lists `contract` first on purpose: a whole-system check runs in the first
listed system's workspace, so `python -m pytest -q tests` runs the contract suite, which
then starts the services from the other two workspaces.

## Scenarios

`scenarios/<id>.yaml`, one per scenario:

| Key               | Meaning                                                                                   |
| ----------------- | ----------------------------------------------------------------------------------------- |
| `id`              | the file name without `.yaml`                                                             |
| `request`         | the engineering request, as a person would write it                                       |
| `systems`         | every system the change touches (all three whenever there is a whole-system test, because the runner only runs a check whose systems are all in the spec) |
| `acceptance`      | a list of `AcceptanceTest` (`a2agw.vsc.spec`)                                              |
| `reference_patch` | a unified diff that solves the scenario, used only to validate it (bench `oracle` mode)    |
| `notes`           | optional remarks for whoever maintains the scenario                                       |

Conventions:

- **Per-system acceptance tests** (`system: <id>`): `files` are relative to that repository's
  root (for example `tests/test_idempotency_key.py`); `run` is unset, so the system's `tests`
  command runs the whole suite with the new file in it.
- **Whole-system acceptance tests** (`system: null`, `check: estate`): no single repository
  owns them, so every `files` path starts with the repository id, for example
  `contract/tests/test_backorders_e2e.py`. They run as part of the `estate` check.
- **`reference_patch`**: one `git diff` over the three repositories, every path prefixed with
  the repository id (`a/orders-api/app.py`, `b/orders-api/app.py`). To apply it, cut it at
  each `diff --git` header, group the parts by the first path component, and in each
  repository run `git apply -p2` on its part, which is the same as stripping the id and
  applying with `-p1`. `tests/vsc/estate_support.py` (`split_patch`, `apply_patch`,
  `split_files`) is the reference implementation.
- Acceptance tests fail by a failing assertion (exit status 1), never by a collection or
  import error, and they bring their own fakes when a scenario needs a fake to behave
  differently, so they do not depend on how a solution changes the existing test helpers.

| Scenario                                    | Systems                 | The change                                                                                              |
| ------------------------------------------- | ----------------------- | ------------------------------------------------------------------------------------------------------- |
| `reserve-stock-on-order`                    | all                     | a refused line must give back the stock reserved for the lines before it (all or nothing)              |
| `release-stock-on-cancel`                   | all                     | cancelling releases the order's stock, once; 502 and still placed if inventory cannot                   |
| `idempotency-key`                           | orders-api, contract    | `Idempotency-Key` on `POST /orders`: replays return the first order, reserve nothing, survive restarts  |
| `backorders-end-to-end`                     | all                     | `allow_backorder` through both services, a `backordered` status and counts, a schema migration         |
| `rename-qty-to-quantity`                    | all                     | a coordinated breaking rename (contract 1.1.0) across services, documents and every test                |
| `order-total-with-tax-from-inventory-price` | all                     | prices from inventory kept with the order; subtotal, tax (`TAX_RATE_BPS`, half up), total               |
| `soft-delete-products`                      | all                     | `DELETE` becomes a soft delete; 410 from inventory becomes "product discontinued" in orders             |
| `pagination-on-list-orders`                 | orders-api, contract    | keyset pagination with an opaque `next_cursor`, stable while orders arrive                              |
| `inventory-low-stock-webhook-to-orders`     | all                     | inventory calls orders back on a threshold crossing; orders stores and lists the alerts                 |
| `contract-version-header`                   | all                     | `X-Contract-Version: 1` on every response and outgoing call; other versions refused                     |

`tests/vsc/test_estate.py` proves each one in the normal test gate: on the estate's base
commits every per-system acceptance test fails through `reproduction_before` and every
whole-system one fails through `verify_whole`; with the reference patch applied and the
acceptance files added, every touched system's gate and tests and the `estate` check pass.
It also checks that the contract suite passes on the base commits.

## Adding a scenario

1. `init_estate.py` a scratch copy, make the change there and write the acceptance tests.
2. Produce the patch from one directory holding the three repositories, for example
   `git diff --no-renames` in a scratch repository that contains `orders-api/`,
   `inventory-service/` and `contract/` side by side, so paths carry the repository id.
3. Write `scenarios/<id>.yaml` with literal block scalars (`|`) for the request, the files
   and the patch. A blank context line of the diff may be written as an empty line (`git
   apply` reads it as one), so the files need no trailing whitespace; a patch that ends in
   such a line needs `|+` so YAML keeps it.
4. `uv run pytest -q tests/vsc/test_estate.py -k <id>`.

The Python suites set `addopts = "--disable-plugin-autoload"` (pytest 8.4 or newer) so the
plugins of whatever environment runs them are not loaded: each repository's tests need
plain pytest only, and startup stays fast.
