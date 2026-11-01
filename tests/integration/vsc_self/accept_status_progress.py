"""Acceptance (core): the invoke protocol's ``status`` event takes an optional ``progress``.

Written into the job's workspace as ``tests/gateway/test_status_progress.py`` by
``tests/integration/test_vsc_self.py``; not collected here (the name has no ``test_`` prefix).
"""

import pytest

from a2agw.core.events import Status
from a2agw.gateway.protocol import ProtocolError, parse_event


@pytest.mark.parametrize("progress", [0, 0.25, 1, 1.0])
def test_status_accepts_progress(progress):
    assert parse_event({"type": "status", "text": "w", "progress": progress}) == Status("w")


def test_status_without_progress_still_works():
    assert parse_event({"type": "status", "text": "w"}) == Status("w")


@pytest.mark.parametrize("progress", [-0.1, 1.5, True, "half", None, float("nan")])
def test_status_refuses_a_bad_progress(progress):
    with pytest.raises(ProtocolError, match="status.progress"):
        parse_event({"type": "status", "text": "w", "progress": progress})
