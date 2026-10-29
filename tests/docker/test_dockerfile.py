"""Static checks of the Dockerfile (they run in the default gate; the image itself is built
by the opt-in ``test_image.py``)."""

from __future__ import annotations

import re
from pathlib import Path

DOCKERFILE = (Path(__file__).resolve().parents[2] / "Dockerfile").read_text()


def test_installs_from_the_lock():
    # Dependencies come from uv.lock (exported, frozen), the project wheel without deps.
    assert "COPY pyproject.toml uv.lock" in DOCKERFILE
    assert re.search(r"uv export --locked --no-dev --no-emit-project", DOCKERFILE)
    assert re.search(r"uv pip install[^\n]*--no-deps", DOCKERFILE)


def test_base_image_is_pinned_by_digest():
    m = re.search(r"^ARG PYTHON_IMAGE=(\S+)$", DOCKERFILE, re.MULTILINE)
    assert m and re.fullmatch(r"python:3\.12-slim@sha256:[0-9a-f]{64}", m.group(1)), m


def test_crewai_guard_is_kept():
    assert "must not contain crewai" in DOCKERFILE
    assert "tr '[:upper:]' '[:lower:]'" in DOCKERFILE
