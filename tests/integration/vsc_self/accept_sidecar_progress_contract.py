"""Acceptance (whole system, check ``sidecar``): core, contract document and Node coder agree
on ``status.progress``.

Written into the job's workspace as ``tests/integration/test_sidecar_progress_contract.py`` by
``tests/integration/test_vsc_self.py`` and run by the ``sidecar`` check from the workspace root,
next to ``test_phase3_demo.py`` (which runs the coder behind a real gateway); not collected here
(the name has no ``test_`` prefix).
"""

import re
from pathlib import Path

from a2agw.gateway.protocol import ProtocolError, parse_event

ROOT = Path.cwd()


def _status_row() -> str:
    text = (ROOT / "docs" / "sidecar.md").read_text()
    rows = [line for line in text.splitlines() if line.startswith("| `status` |")]
    assert len(rows) == 1, rows
    return rows[0]


def test_contract_documents_progress():
    fields = _status_row().split("|")[2]
    assert "`progress?`" in fields  # optional, as the core treats it
    assert "0 to 1" in _status_row()


def test_core_accepts_what_the_contract_documents():
    parse_event({"type": "status", "text": "w", "progress": 0.5})
    try:
        parse_event({"type": "status", "text": "w", "progress": 2})
    except ProtocolError:
        pass
    else:
        raise AssertionError("progress above 1 must be a protocol error")


def test_node_coder_sends_progress_on_every_status():
    source = (ROOT / "examples" / "node_coder" / "agent.mjs").read_text()
    statuses = re.findall(r'emit\(\{ type: "status",[^}]*\}\)', source)
    assert statuses
    assert all("progress:" in s for s in statuses), statuses
