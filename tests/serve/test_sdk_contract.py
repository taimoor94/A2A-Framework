"""The private a2a-sdk hooks the gateway overrides, and the pin that protects them.

``serve/host.py`` overrides two private SDK methods: ``LimitedRequestHandler._setup_active_task``
(``DefaultRequestHandler``; inbound idempotency fills the ledger there) and
``_Compat03Adapter._process_non_streaming_request`` (``JSONRPC03Adapter``; keeps A2A error codes
on 0.3 JSON-RPC requests). A minor SDK release can change either, so ``a2a-sdk`` is pinned to the
tested minor. Before raising the pin, re-verify both overrides against the new SDK, then run this
file and the TCK (``scripts/run_tck.sh``).
"""

from __future__ import annotations

import inspect
import tomllib
from collections.abc import Callable
from pathlib import Path

from packaging.requirements import Requirement
from packaging.version import Version

# Imported first: it loads ``a2a.server.routes`` before the 0.3 adapter (a circular import
# otherwise), exactly as the gateway does.
from a2agw.serve.host import LimitedRequestHandler, _Compat03Adapter  # isort: skip
from a2a.compat.v0_3.jsonrpc_adapter import JSONRPC03Adapter
from a2a.server.request_handlers import DefaultRequestHandler

ROOT = Path(__file__).resolve().parents[2]

_REVERIFY = (
    "the a2a-sdk private hook {hook} changed: re-verify the override {override} in "
    "src/a2agw/serve/host.py against the new SDK before raising the a2a-sdk pin"
)


def _params(fn: Callable[..., object]) -> list[str]:
    return list(inspect.signature(fn).parameters)


def test_private_hooks_exist_with_expected_signatures():
    base_name = {
        DefaultRequestHandler: "DefaultRequestHandler",
        JSONRPC03Adapter: "JSONRPC03Adapter",
    }
    hooks = [
        (
            DefaultRequestHandler,
            "_setup_active_task",
            LimitedRequestHandler,
            ["self", "params", "call_context"],
        ),
        (
            JSONRPC03Adapter,
            "_process_non_streaming_request",
            _Compat03Adapter,
            ["self", "request_id", "request_obj", "context"],
        ),
    ]
    for base, name, sub, expected in hooks:
        # Named as host.py imports it (``DefaultRequestHandler`` aliases a V2 class in 1.2).
        hook = f"{base_name[base]}.{name}"
        override = f"{sub.__name__}.{name}"
        msg = _REVERIFY.format(hook=hook, override=override)
        assert name in vars(base), f"{msg} (the hook is gone)"
        assert _params(getattr(base, name)) == expected, msg
        # The override itself still takes the same parameters as the hook it replaces.
        assert name in vars(sub), override
        assert _params(getattr(sub, name)) == expected, msg


def test_sdk_pin_is_a_minor_range():
    cfg = tomllib.loads((ROOT / "pyproject.toml").read_text())
    reqs = [Requirement(d) for d in cfg["project"]["dependencies"]]
    (sdk,) = [r for r in reqs if r.name == "a2a-sdk"]
    lower = [Version(s.version) for s in sdk.specifier if s.operator == ">="]
    upper = [Version(s.version) for s in sdk.specifier if s.operator == "<"]
    assert len(lower) == 1 and len(upper) == 1, str(sdk.specifier)
    low = lower[0]
    next_minor = Version(f"{low.major}.{low.minor + 1}")
    assert upper[0] == next_minor, (
        f"a2a-sdk must be pinned below the next minor ({next_minor}), not {upper[0]}: "
        "see tests/serve/test_sdk_contract.py"
    )
