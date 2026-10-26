"""The dev environment has every framework the adapter tests need.

Adapter test modules skip themselves (``pytest.importorskip``) when their framework is not
installed, so a missing dev dependency would turn a whole module green while testing
nothing. This test fails instead. Add each new adapter's framework here (CrewAI excepted: it
runs in its own environment).
"""

from __future__ import annotations

import importlib

import pytest

# Real modules, not bare package names: "langgraph" alone is a namespace package that
# langgraph-checkpoint also provides, so it imports even without langgraph itself.
DEV_FRAMEWORKS = [
    "langchain_core",
    "langgraph.graph",
    "langgraph.checkpoint.sqlite",
    "asyncpg",
    "agents",
    "mcp",
    "claude_agent_sdk",
    "google.adk",
    "ag2",
]


@pytest.mark.parametrize("module", DEV_FRAMEWORKS)
def test_framework_installed(module):
    try:
        importlib.import_module(module)
    except ImportError as e:
        pytest.fail(f"{module} is missing from the dev environment (uv sync): {e}")
