"""The control plane: a service gateways connect to, owning partners, policies, users, roles.

Needs the ``control`` extra (FastAPI). Only ``a2agw.control.app`` and the modules it serves
(``rbac``, ``authn``) import FastAPI; this package, its settings, store and CLI do not, so
``import a2agw.control`` works without the extra and ``require_fastapi`` turns a missing
extra into a one-line install hint.
"""

from __future__ import annotations

from types import ModuleType

INSTALL_HINT = "the control plane needs the control extra: pip install 'a2a-gateway[control]'"


def require_fastapi() -> ModuleType:
    """The ``fastapi`` module; ``ImportError`` with the install hint if it is missing."""
    try:
        import fastapi
    except ImportError:
        raise ImportError(INSTALL_HINT) from None
    return fastapi


def control_available() -> bool:
    """Whether the control extra is installed (checked without importing FastAPI)."""
    import importlib.util
    import sys

    if "fastapi" in sys.modules:
        return sys.modules["fastapi"] is not None
    try:
        return importlib.util.find_spec("fastapi") is not None
    except (ImportError, ValueError):
        return False
