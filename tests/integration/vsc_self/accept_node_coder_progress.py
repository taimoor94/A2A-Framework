"""Acceptance (node-coder): the Node coder's ``status`` events carry ``progress`` (0 to 1).

Written into the job's workspace as ``tests/integration/test_node_coder_progress.py`` by
``tests/integration/test_vsc_self.py``; not collected here (the name has no ``test_`` prefix).
The coder runs on its own (no gateway), so this checks the Node side only.
"""

import json
import time

import httpx

from a2agw.gateway.protocol import sign
from examples.software_team import run_demo

SECRET = "node-progress-secret"


async def test_node_coder_reports_progress():
    node = run_demo.NodeCoder(SECRET)
    url = await node.start()
    try:
        body = json.dumps(
            {
                "protocol": "a2agw.invoke/1",
                "agent_id": "coder",
                "task_id": "t1",
                "context_id": "c1",
                "resumed": False,
                "text": "write fizzbuzz",
                "parts": [{"text": "write fizzbuzz"}],
                "metadata": {},
                "caller": None,
                "consult": None,
                "deadline": None,
            }
        ).encode()
        ts = str(int(time.time()))
        headers = {
            "content-type": "application/json",
            "x-a2agw-timestamp": ts,
            "x-a2agw-signature": sign(SECRET, ts, body),
        }
        async with httpx.AsyncClient(timeout=30) as hc:
            r = await hc.post(url, content=body, headers=headers)
    finally:
        await node.stop()
    assert r.status_code == 200, r.text
    events = [json.loads(line) for line in r.text.splitlines() if line]
    statuses = [e for e in events if e["type"] == "status"]
    assert statuses, events
    for e in statuses:
        p = e.get("progress")
        assert isinstance(p, int | float) and not isinstance(p, bool) and 0 <= p <= 1, e
