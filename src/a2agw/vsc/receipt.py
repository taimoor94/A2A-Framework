"""The receipt: the exportable, offline-verifiable record of a job (spec, plan, every step
attempt and check, approvals, usage), bound to the gateway's audit chain.

``build_receipt`` collects the job's audit rows, hashes the bundle and then appends exactly one
``vsc.receipt`` audit row carrying that hash, so the receipt is anchored in the chain after the
fact. Diffs are never stored, only their sha256 (taken from the step's recorded result).
``verify_receipt`` needs nothing but the bundle: it recomputes the receipt, spec and plan
hashes and each embedded audit row's digest.

The bundle's audit rows are the contiguous slice of the chain from the job's first row to its
last. Only the job's own rows are embedded in full; every other row in the span (a concurrent
job's) is an opaque stub ``{seq, prev_hash, hash}`` that keeps the chain linkable without
disclosing anything. The first row's ``prev_hash`` is trusted as given; every later row must link
to the one before it.

The receipt cites the job's audit rows: every step attempt, check and approval carries the
``audit_seq`` of its row, and ``audit.job_seqs`` / ``audit.job_rows`` list and count all of the
job's rows in the span. What offline verification proves: the bundle is internally consistent
(hashes, chain links) and the job's own rows are complete relative to what the receipt claims
(every cited and listed seq is present as a full row of this job, none is a stub, no further
row of this job hides in the span). It does not prove the bundle is the gateway's: a forger who
rewrites the claims and recomputes every hash is caught only by comparing ``receipt_hash`` with
the gateway's ``vsc.receipt`` row."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

from a2agw.ops.audit import AuditEvent, AuditLog, canonical_json, row_digest
from a2agw.vsc.plan import Plan, plan_hash
from a2agw.vsc.spec import ExecutableSpec, spec_hash
from a2agw.vsc.store import VscStore

VERSION = "a2agw.receipt/1"
_AGENT = "deliver"
_PAGE = 500
_FINISHED = ("accepted", "failed", "cancelled")
_STUB_KEYS = {"seq", "prev_hash", "hash"}
_locks: dict[str, asyncio.Lock] = {}


def _hash(receipt: dict[str, Any]) -> str:
    body = {k: v for k, v in receipt.items() if k != "receipt_hash"}
    return hashlib.sha256(canonical_json(body).encode()).hexdigest()


async def _slice(audit: AuditLog, job_id: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(the job's own rows, the contiguous chain slice from the job's first row to its last)."""
    mine: list[dict[str, Any]] = []
    cursor: str | None = None
    while True:
        rows, cursor = await audit.query({"agent": _AGENT}, _PAGE, cursor, ascending=True)
        mine += [r for r in rows if r["task_id"] == job_id]
        if cursor is None:
            break
    if not mine:
        return [], []
    first, last = mine[0]["seq"], mine[-1]["seq"]
    chain: list[dict[str, Any]] = []
    cursor = str(first - 1) if first > 1 else None
    while True:
        rows, cursor = await audit.query({}, _PAGE, cursor, ascending=True)
        chain += [
            r if r["task_id"] == job_id else {k: r[k] for k in sorted(_STUB_KEYS)}
            for r in rows
            if r["seq"] <= last
        ]
        if cursor is None or not rows or rows[-1]["seq"] >= last:
            return mine, chain


def _loads(text: str | None) -> dict[str, Any]:
    return json.loads(text) if text else {}


async def build_receipt(store: VscStore, audit: AuditLog, job_id: str) -> dict[str, Any]:
    """The job's receipt, built once: a repeat returns the stored one. Diff hashes come from the
    attempts' recorded results. A job that has not finished has no receipt."""
    lock = _locks.setdefault(job_id, asyncio.Lock())
    try:
        async with lock:
            return await _build(store, audit, job_id)
    finally:
        if not lock.locked() and not getattr(lock, "_waiters", None):
            _locks.pop(job_id, None)


def _find_seq(
    rows: list[dict[str, Any]],
    action: str,
    step: str | None,
    attempt: int | None,
    outcome: str | None,
) -> int | None:
    for r in rows:
        d = r["detail"] or {}
        if (
            r["action"] == action
            and d.get("step") == step
            and (attempt is None or d.get("attempt") == attempt)
            and (outcome is None or r["outcome"] == outcome)
        ):
            return int(r["seq"])
    return None


async def _build(store: VscStore, audit: AuditLog, job_id: str) -> dict[str, Any]:
    existing = await store.get_receipt(job_id)
    if existing is not None:
        return existing["receipt"]
    job = await store.get_job(job_id)
    if job is None:
        raise KeyError(f"unknown job {job_id}")
    if job["state"] not in _FINISHED:
        raise ValueError("job is not finished")
    rows, chain = await _slice(audit, job_id)
    steps: list[dict[str, Any]] = []
    approvals: list[dict[str, Any]] = [
        {
            "step": r["detail"].get("step"),
            "outcome": r["outcome"],
            "actor": r["actor"],
            "note": r["detail"].get("note", ""),
            "auto": False,
            "audit_seq": r["seq"],
        }
        for r in rows
        if r["action"] == "vsc.approve"
    ]
    for a in await store.attempts(job_id):
        if a["attempt"] <= 0:
            continue
        result, usage = _loads(a["result_json"]), _loads(a["usage_json"])
        approval = result.get("approval")
        if isinstance(approval, dict) and approval.get("auto"):
            approvals.append({"step": a["step_id"], **approval, "outcome": "approved"})
        checks = [
            {**c, "audit_seq": _find_seq(rows, "vsc.check", a["step_id"], a["attempt"], None)}
            if isinstance(c, dict)
            else c
            for c in result.get("checks", [])
        ]
        steps.append(
            {
                "step_id": a["step_id"],
                "attempt": a["attempt"],
                "system": a["system"],
                "kind": a["kind"],
                "state": a["state"],
                "worker": a["worker"],
                "usage": {k: usage.get(k, 0) for k in ("tokens_in", "tokens_out", "cost")},
                "usage_reported": bool(usage.get("usage_reported", False)),
                "audit_seq": _find_seq(rows, "vsc.step", a["step_id"], a["attempt"], "worker"),
                "checks": checks,
                "diff_sha256": result.get("diff_sha256"),
                "commit": result.get("commit"),
            }
        )
    receipt: dict[str, Any] = {
        "version": VERSION,
        "job_id": job_id,
        "state": job["state"],
        "spec": _loads(job["spec_json"]),
        "spec_hash": job["spec_hash"],
        "plan": _loads(job["plan_json"]),
        "plan_hash": job["plan_hash"],
        "tasks": sorted({r["task_id"] for r in rows if r["action"] == "vsc.job"}),
        "steps": steps,
        "whole_checks": [
            {"outcome": r["outcome"], "audit_seq": r["seq"]}
            for r in rows
            if r["action"] == "vsc.check" and "step" not in (r["detail"] or {})
        ],
        "approvals": approvals,
        "usage": {
            "tokens_in": job["tokens_in"],
            "tokens_out": job["tokens_out"],
            "cost": job["cost"],
            "attempts": job["attempts"],
            "active_s": job["active_s"],
            "whole_passed": bool(job["whole_passed"]),
        },
        "audit": {
            "first_seq": chain[0]["seq"] if chain else None,
            "last_seq": chain[-1]["seq"] if chain else None,
            "job_rows": len(rows),
            "job_seqs": [r["seq"] for r in rows],
            "rows": chain,
        },
        "created_at": time.time(),
    }
    receipt["receipt_hash"] = _hash(receipt)
    seq = await audit.append(
        AuditEvent(
            actor="system",
            action="vsc.receipt",
            agent_id=_AGENT,
            task_id=job_id,
            outcome=job["state"],
            detail={"receipt_hash": receipt["receipt_hash"]},
        )
    )
    await store.put_receipt(job_id, receipt, receipt["receipt_hash"], seq)
    return receipt


def export_receipt(receipt: dict[str, Any], path: Path) -> None:
    fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        os.fchmod(f.fileno(), 0o600)  # an existing file keeps its old mode otherwise
        f.write(json.dumps(receipt, sort_keys=True, indent=2, ensure_ascii=False))
        f.write("\n")


def _audit_problems(receipt: dict[str, Any]) -> list[str]:
    audit = receipt.get("audit")
    rows = audit.get("rows") if isinstance(audit, dict) else None
    if not isinstance(rows, list):
        return ["audit: rows missing"]
    problems: list[str] = []
    prev: dict[str, Any] | None = None
    for row in rows:
        try:
            if not isinstance(row, dict):
                raise TypeError("row is not an object")
            if set(row) != _STUB_KEYS and row_digest(row) != row["hash"]:
                problems.append(f"audit: row {row.get('seq')} hash mismatch")
            if prev is not None:
                if row["seq"] <= prev["seq"]:
                    problems.append(f"audit: row {row['seq']} out of order")
                elif row["seq"] != prev["seq"] + 1 or row["prev_hash"] != prev["hash"]:
                    problems.append(f"audit: row {row['seq']} breaks the chain")
        except (KeyError, TypeError):
            problems.append("audit: malformed row")
            break
        prev = row
    dicts = [r for r in rows if isinstance(r, dict)]
    if (
        dicts
        and len(dicts) == len(rows)
        and (audit.get("first_seq"), audit.get("last_seq"))
        != (rows[0].get("seq"), rows[-1].get("seq"))
    ):
        problems.append("audit: first_seq/last_seq do not match the rows")
    for row in dicts:
        if (
            row.get("action") == "vsc.receipt"
            and row.get("task_id") == receipt.get("job_id")
            and (row.get("detail") or {}).get("receipt_hash") != receipt.get("receipt_hash")
        ):
            problems.append("audit: vsc.receipt row does not match receipt_hash")
    problems += _completeness_problems(receipt, rows)
    return problems


def _cited(receipt: dict[str, Any]) -> list[Any]:
    cited: list[Any] = []
    for key in ("steps", "approvals", "whole_checks"):
        items = receipt.get(key)
        for item in items if isinstance(items, list) else []:
            if not isinstance(item, dict):
                continue
            cited.append(item.get("audit_seq"))
            checks = item.get("checks")
            for c in checks if isinstance(checks, list) else []:
                if isinstance(c, dict):
                    cited.append(c.get("audit_seq"))
    return [c for c in cited if c is not None]


def _completeness_problems(receipt: dict[str, Any], rows: list[Any]) -> list[str]:
    audit = receipt["audit"]
    job_id = receipt.get("job_id")
    full = {
        r.get("seq"): r for r in rows if isinstance(r, dict) and set(r) != _STUB_KEYS and "seq" in r
    }
    seqs = audit.get("job_seqs")
    if not isinstance(seqs, list):
        return ["audit: job_seqs missing"]
    problems: list[str] = []
    listed = set(seqs)
    for seq in sorted({*seqs, *_cited(receipt)}, key=repr):
        row = full.get(seq)
        if row is None:
            problems.append(f"audit: job row {seq} is missing or a stub")
        elif row.get("task_id") != job_id:
            problems.append(f"audit: row {seq} does not belong to the job")
        elif seq not in listed:
            problems.append(f"audit: cited row {seq} is not in job_seqs")
    mine = [s for s, r in full.items() if r.get("task_id") == job_id]
    problems += [f"audit: job row {s} is not in job_seqs" for s in mine if s not in listed]
    if audit.get("job_rows") != len(mine):
        problems.append("audit: job_rows does not match the full job rows")
    return problems


def verify_receipt(bundle: dict[str, Any]) -> list[str]:
    """Problems found in an exported receipt (empty = valid)."""
    problems: list[str] = []
    if bundle.get("version") != VERSION:
        problems.append("version: unsupported")
    try:
        if bundle.get("receipt_hash") != _hash(bundle):
            problems.append("receipt_hash: does not match the bundle")
    except (TypeError, ValueError):
        problems.append("receipt_hash: bundle is not serialisable")
    try:
        if spec_hash(ExecutableSpec.model_validate(bundle.get("spec"))) != bundle.get("spec_hash"):
            problems.append("spec_hash: does not match the spec")
    except ValueError:
        problems.append("spec_hash: spec is invalid")
    try:
        if plan_hash(Plan.model_validate(bundle.get("plan"))) != bundle.get("plan_hash"):
            problems.append("plan_hash: does not match the plan")
    except ValueError:
        problems.append("plan_hash: plan is invalid")
    return problems + _audit_problems(bundle)
