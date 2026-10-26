"""A fake external agent for StdioAdapter tests: ``a2agw.invoke/1`` over JSON lines.

Run as ``python -I stdio_agent.py <mode> [record]``. Standard library only; it must not import
a2agw. Every op received is appended to ``record`` (one JSON line each) when given.

Modes (the whole process):

- ``serve``: answer each invoke by its ``text`` (see ``answer``).
- ``gather:<n>``: hold invokes until ``n`` have arrived, then answer them in reverse order.
- ``crash-after-first``: the first process (no ``<record>.crashed`` marker yet) creates the
  marker, waits for three invokes and exits with code 3 without answering; later processes
  behave as ``serve``.
- ``stubborn``: as ``serve``, but ignores the shutdown op, stdin EOF and SIGTERM.
- ``exit``: exits with code 1 at once.

Per-invoke ``text`` in ``serve``: ``block`` streams a status and never ends; ``env`` reports
the environment; ``stderr`` writes a long and a short stderr line; ``malformed`` sends an
invalid event; ``garbage`` sends unparseable lines first; anything else is echoed.
"""

import json
import os
import signal
import sys
import time

MODE = sys.argv[1]
RECORD = sys.argv[2] if len(sys.argv) > 2 else None


def record(op):
    if RECORD:
        with open(RECORD, "a") as f:
            f.write(json.dumps(op) + "\n")


def emit(rid, event):
    sys.stdout.write(json.dumps({"id": rid, "event": event}) + "\n")
    sys.stdout.flush()


def answer(rid, req):
    text = req["text"]
    if text == "block":
        emit(rid, {"type": "status", "text": "working"})
        return
    if text == "env":
        report = {
            "secret": "A2AGW_TEST_SECRET" in os.environ,
            "other": "A2AGW_TEST_OTHER" in os.environ,
            "given": os.environ.get("GIVEN"),
            "cwd": os.getcwd(),
        }
        emit(rid, {"type": "done", "text": json.dumps(report)})
        return
    if text == "stderr":
        sys.stderr.write("x" * 10000 + "\n" + "hello-stderr\n")
        sys.stderr.flush()
        emit(rid, {"type": "done"})
        return
    if text == "malformed":
        emit(rid, {"type": "bogus"})
        return
    if text == "garbage":
        sys.stdout.write("{not json\n" + json.dumps({"event": {"type": "done"}}) + "\n\n")
        sys.stdout.flush()
    emit(rid, {"type": "status", "text": "on it"})
    emit(rid, {"type": "text", "text": "echo: "})
    emit(rid, {"type": "text", "text": text})
    emit(rid, {"type": "usage", "tokens_in": 1, "tokens_out": 2, "cost": 0.5})
    emit(rid, {"type": "done"})


def main():
    mode = MODE
    gather = int(mode.split(":")[1]) if mode.startswith("gather:") else 0
    crashing = False
    if mode == "exit":
        sys.exit(1)
    if mode == "crash-after-first":
        marker = RECORD + ".crashed"
        if not os.path.exists(marker):
            open(marker, "w").close()
            crashing = True
    if mode == "stubborn":
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    held = []
    for raw in sys.stdin:
        op = json.loads(raw)
        record(op)
        if op["op"] == "shutdown":
            if mode == "stubborn":
                continue
            return
        if op["op"] != "invoke":
            continue
        if crashing:
            held.append(op)
            if len(held) == 3:
                os._exit(3)
            continue
        if gather:
            held.append(op)
            if len(held) == gather:
                for h in reversed(held):
                    emit(h["id"], {"type": "done", "text": "reply-" + h["request"]["text"]})
                held = []
            continue
        answer(op["id"], op["request"])
    if mode == "stubborn":  # stdin closed: keep running until killed
        while True:
            time.sleep(60)


main()
