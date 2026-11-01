"""Phase 5a "done when", second half: VSC delivers a change across two (here three) declared
systems of *this* repository, end to end, as one local branch with an offline-verified receipt.

The job runs on a throwaway clone of this repository's HEAD (``git clone --no-hardlinks`` into
``tmp_path``), so the real checkout is never touched. Its ``vsc:`` section is this repository's
own, read from ``docs/vsc.md`` (see ``self_config``): ``core`` (``src/a2agw``), ``node-coder`` (``examples/node_coder``),
``sidecar-contract`` (``docs/sidecar.md``) and the whole-system check ``sidecar``, which runs
the real ``tests/integration/test_phase3_demo.py`` (about 15 s: the Node coder behind a real
gateway) plus the job's whole-system acceptance test.

The request: an optional ``progress`` field on the invoke protocol's ``status`` event. The
three parts depend on each other: once the Node coder sends ``progress``, a gateway without the
core change refuses the event as a protocol error and the phase 3 demo fails; the contract
document must say what the core accepts. The planner is scripted and the worker is the
fake worker (``tests/vsc/worker_agent.py``) in its ``patch`` mode, fed each system's part of the
reference solution (``vsc_self/reference.patch``): ``docs/sidecar.md`` alone is larger than a
step's 16 KiB instructions, so whole files (the ``apply`` mode) cannot be sent.
The acceptance tests (``vsc_self/accept_*.py``) are proved to fail on the base before the job.

The clone is of the committed HEAD (a dirty working tree is not cloned), so ``reference.patch``
must apply to the committed HEAD. The clone's branch is pinned to ``main`` (``checkout -B``), so
a detached HEAD in CI cannot make ``default_branch`` ``HEAD``.

If ``reference.patch`` stops applying (the three files changed), regenerate it: make the change
in a scratch clone and ``git diff --no-renames`` there.

Commands run under this interpreter with ``PYTHONPATH`` pointing at the clone's ``src`` (via
``env``), never ``uv run``: uv would build a new virtual environment inside the clone, and the
installed ``a2agw`` (an editable install of the real checkout) must not shadow the clone's.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from a2agw.ops.audit import AuditLog
from a2agw.serve.store import create_engine
from a2agw.vsc.config import VscConfig
from a2agw.vsc.gate import Gate
from a2agw.vsc.plan import Plan, PlanStep
from a2agw.vsc.planner import ScriptedPlanner
from a2agw.vsc.receipt import build_receipt, verify_receipt
from a2agw.vsc.runner import JobRunner
from a2agw.vsc.spec import AcceptanceTest, Contract, ExecutableSpec
from a2agw.vsc.store import VscStore
from a2agw.vsc.verify import reproduction_before, run_check
from a2agw.vsc.workers import WorkerSpec
from a2agw.vsc.workspace import WorkspaceManager

if shutil.which("node") is None and os.environ.get("CI"):
    raise RuntimeError("node is not on PATH, but CI is set: the self test must not be skipped")

pytestmark = [
    pytest.mark.skipif(shutil.which("node") is None, reason="node is not on PATH"),
    pytest.mark.timeout(600),
]

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent / "vsc_self"
WORKER_AGENT = ROOT / "tests" / "vsc" / "worker_agent.py"
PY = sys.executable
ENV = shutil.which("env") or "/usr/bin/env"
REPO_ID = "a2agw"  # the clone's directory name, so the workspace's repository id
FILES = {
    "core": "src/a2agw/gateway/protocol.py",
    "node-coder": "examples/node_coder/agent.mjs",
    "sidecar-contract": "docs/sidecar.md",
}
# acceptance source in vsc_self/ -> path in the workspace (repository-relative)
CORE_TEST = "tests/gateway/test_status_progress.py"
NODE_TEST = "tests/integration/test_node_coder_progress.py"
WHOLE_TEST = "tests/integration/test_sidecar_progress_contract.py"
REQUEST = (
    "Add an optional `progress` field to the invoke protocol's `status` event: a number from 0 "
    "to 1 saying how far the turn is. The gateway accepts and validates it (anything else stays "
    "a protocol error), docs/sidecar.md documents it, and the Node coder reports it."
)


def _pytest(pythonpath: str, *tests: str) -> list[str]:
    """pytest under this interpreter with the clone's ``src`` first on the import path."""
    return [ENV, f"PYTHONPATH={pythonpath}", PY, "-m", "pytest", "-q", "-p", "no:cacheprovider",
            *tests]  # fmt: skip


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True, text=True, timeout=120
    ).stdout.strip()


def documented_config() -> VscConfig:
    """The ``vsc:`` block of ``docs/vsc.md`` (the yaml block after the marker comment)."""
    text = (ROOT / "docs" / "vsc.md").read_text()
    _, marker, rest = text.partition("<!-- vsc-self-config:")
    assert marker, "docs/vsc.md lost its vsc-self-config marker"
    m = re.search(r"```yaml\n(.*?)```", rest, re.DOTALL)
    assert m is not None
    return VscConfig.model_validate(yaml.safe_load(m.group(1))["vsc"])


def self_config(repo: Path, branch: str) -> VscConfig:
    """This repository's documented ``vsc:`` section pointed at ``repo``: every system's
    repository is the clone, its default branch the clone's branch, ``python`` this interpreter.
    Two changes for speed and for the job: ``core``'s tests are narrowed to
    ``tests/gateway/test_protocol.py``, and the ``sidecar`` check also runs the job's
    whole-system acceptance test."""
    doc = documented_config()
    assert [s.id for s in doc.systems] == ["core", "node-coder", "sidecar-contract", "docker"]
    assert [c.id for c in doc.checks] == ["sidecar", "compose"]
    # Documented only (not executed): `docker`, `compose`; check their shape and referenced paths.
    docker = next(s for s in doc.systems if s.id == "docker")
    compose = next(c for c in doc.checks if c.id == "compose")
    assert (ROOT / docker.path).is_dir(), docker.path
    for arg in [*(docker.tests or []), *compose.run]:
        if "/" in arg and not arg.startswith("PYTHONPATH") and arg != "/opt/vsc-bridges/claude_code.py":
            base = ROOT / docker.path if arg.startswith("../") else ROOT
            assert (base / arg).exists(), arg

    def cmd(command: list[str] | None) -> list[str] | None:
        return None if command is None else [PY if a == "python" else a for a in command]

    systems = []
    for s in doc.systems:
        if s.id == "docker":
            continue  # documented only
        tests = _pytest("..", "../../tests/gateway/test_protocol.py") if s.id == "core" else s.tests
        systems.append(
            s.model_copy(
                update={
                    "repo": str(repo),
                    "default_branch": branch,
                    "gate": cmd(s.gate),
                    "tests": cmd(tests),
                }
            )
        )
    checks = []
    for c in doc.checks:
        if c.id == "compose":
            continue  # documented only
        run = cmd(c.run)
        assert run is not None
        if c.id == "sidecar":
            assert "tests/integration/test_phase3_demo.py" in run
            run = [*run, WHOLE_TEST]
        checks.append(c.model_copy(update={"run": run}))
    return doc.model_copy(update={"systems": systems, "checks": checks, "workers": []})


def reference_parts() -> dict[str, str]:
    """``reference.patch`` cut at each ``diff --git`` header, by the system of its file."""
    patch = (HERE / "reference.patch").read_text()
    starts = [m.start() for m in re.finditer(r"^diff --git ", patch, re.MULTILINE)]
    by_file = {
        re.match(r"diff --git a/(\S+) ", patch[s:e]).group(1): patch[s:e]  # type: ignore[union-attr]
        for s, e in zip(starts, [*starts[1:], len(patch)], strict=True)
    }
    assert set(by_file) == set(FILES.values()), sorted(by_file)
    return {sid: by_file[rel] for sid, rel in FILES.items()}


def reference_files(repo: Path) -> dict[str, str]:
    """Each changed file's content with ``reference.patch`` applied to the clone's HEAD (in a
    throwaway worktree, so the clone itself stays at its base)."""
    tmp = repo.parent / "reference"
    _git(repo, "worktree", "add", "--detach", str(tmp), "HEAD")
    try:
        subprocess.run(
            ["git", "apply", "--whitespace=nowarn", str(HERE / "reference.patch")],
            cwd=tmp,
            check=True,
            capture_output=True,
            text=True,
        )
        return {sid: (tmp / rel).read_text() for sid, rel in FILES.items()}
    finally:
        _git(repo, "worktree", "remove", "--force", str(tmp))


def acceptance() -> list[AcceptanceTest]:
    def read(name: str) -> str:
        return (HERE / name).read_text()

    return [
        AcceptanceTest(
            id="core-accepts-progress",
            system="core",
            files={CORE_TEST: read("accept_status_progress.py")},
            run=_pytest("..", f"../../{CORE_TEST}"),
        ),
        AcceptanceTest(
            id="node-coder-reports-progress",
            system="node-coder",
            files={NODE_TEST: read("accept_node_coder_progress.py")},
            run=_pytest("../../src", f"../../{NODE_TEST}"),
        ),
        AcceptanceTest(
            id="contract-documents-progress",
            check="sidecar",
            files={f"{REPO_ID}/{WHOLE_TEST}": read("accept_sidecar_progress_contract.py")},
        ),
    ]


class SelfPlanner(ScriptedPlanner):
    """Scripted intake (the spec above) and a fixed plan: core first, then the Node coder and
    the contract, each step's instructions ending with its part of the reference patch."""

    def __init__(self, spec: ExecutableSpec, parts: dict[str, str]) -> None:
        super().__init__(spec_for=lambda _request: spec)
        self._parts = parts

    async def plan(self, spec: ExecutableSpec) -> Plan:
        def step(sid: str, what: str, deps: list[str]) -> PlanStep:
            return PlanStep(
                id=f"edit-{sid}",
                system=sid,
                depends_on=deps,
                contracts=["a2agw.invoke/1"],
                instructions=f"{what}\n---PATCH---\n{self._parts[sid]}",
            )

        return Plan(
            steps=[
                step("core", "Accept and validate status.progress in parse_event.", []),
                step("node-coder", "Report progress on the coder's status events.", ["edit-core"]),
                step("sidecar-contract", "Document status.progress.", ["edit-core"]),
            ]
        )


def system_of(path: str) -> str | None:
    for sid, prefix in (("core", "src/a2agw/"), ("node-coder", "examples/node_coder/")):
        if path.startswith(prefix):
            return sid
    return "sidecar-contract" if path == "docs/sidecar.md" else None


async def test_vsc_delivers_change_across_core_and_node_coder(tmp_path):
    def tracked_state() -> tuple[str, str]:  # tracked files only: parallel runs add untracked ones
        return _git(ROOT, "rev-parse", "HEAD"), _git(
            ROOT, "status", "--porcelain", "--untracked-files=no"
        )

    real_state = tracked_state()
    repo = tmp_path / REPO_ID
    _git(tmp_path, "clone", "-q", "--no-hardlinks", str(ROOT), str(repo))
    branch = "main"
    _git(repo, "checkout", "-q", "-B", branch)  # never "HEAD", whatever the checkout state
    base = _git(repo, "rev-parse", "HEAD")
    cfg = self_config(repo, branch)
    systems = {s.id: s for s in cfg.systems}
    tests = acceptance()
    spec = ExecutableSpec(
        request=REQUEST,
        done="status.progress is accepted by the core, documented and sent by the Node coder",
        systems=["core", "node-coder", "sidecar-contract"],
        acceptance=tests,
        contracts=[Contract(name="a2agw.invoke/1", systems=list(FILES))],
        budgets=cfg.budgets,
    )
    files = reference_files(repo)
    assert all(files[sid] != (repo / rel).read_text() for sid, rel in FILES.items())

    engine = await create_engine(f"sqlite+aiosqlite:///{tmp_path / 'gateway.db'}")
    store, audit = VscStore(engine), AuditLog(engine)
    await store.initialize()
    await audit.initialize()
    workspaces = WorkspaceManager(tmp_path / "workspaces", cfg.systems, tmp_path)
    try:
        # The acceptance tests are real: every one fails on the base commit.
        probe = await workspaces.create("probe", "core")
        for test in tests[:2]:
            assert test.system is not None
            res = await reproduction_before(
                workspaces, probe, test, systems[test.system], timeout_s=120
            )
            assert res.passed, (test.id, res.reason, res.stderr_tail)
        async with workspaces.throwaway(probe) as tmp:
            (tmp / WHOLE_TEST).write_text(tests[2].files[f"{REPO_ID}/{WHOLE_TEST}"])
            res = await run_check(
                "reproduction_before", tests[2].id, _pytest("src", WHOLE_TEST), tmp, timeout_s=120
            )
            assert res.exit_code == 1, (res.reason, res.stderr_tail)
        await workspaces.discard("probe")

        worker = WorkerSpec(
            id="patch", command=[PY, "-I", str(WORKER_AGENT), "patch"], cost_class="cheap"
        )
        planner = SelfPlanner(spec, reference_parts())
        runner = JobRunner(
            store=store,
            workspaces=workspaces,
            workers=[worker],
            planner_factory=lambda _job_id: planner,
            cfg=cfg,
            audit=audit,
            bus=None,
            consult=None,
            gate=Gate(cfg, audit),
        )
        job_id = await runner.submit(REQUEST, owner="self-test")
        job = await runner.run(job_id)
        attempts = await store.attempts(job_id)
        assert job["state"] == "accepted", (job, attempts)

        # Every step passed on its first attempt, each with its own commit on one branch.
        assert [(a["step_id"], a["attempt"], a["state"]) for a in attempts if a["attempt"]] == [
            ("edit-core", 1, "passed"),
            ("edit-node-coder", 1, "passed"),
            ("edit-sidecar-contract", 1, "passed"),
        ]
        job_branch = f"vsc/{job_id}/{REPO_ID}"
        log = _git(repo, "log", "--format=%s", f"{base}..{job_branch}").splitlines()
        assert len(log) == 3 and all(job_id in line for line in log), log
        changed = _git(repo, "diff", "--name-only", base, job_branch).splitlines()
        assert set(FILES.values()) <= set(changed), changed
        touched = {system_of(p) for p in changed} - {None}
        assert touched == set(FILES), changed  # three systems changed in one branch
        for sid, rel in FILES.items():
            assert _git(repo, "show", f"{job_branch}:{rel}") == files[sid].rstrip("\n")
        assert _git(repo, "rev-parse", branch) == base  # nothing merged into the base branch

        # The sidecar whole-system check ran and passed.
        receipt = await build_receipt(store, audit, job_id)
        assert [c["outcome"] for c in receipt["whole_checks"]] == ["passed"]
        rows, _ = await audit.query({"action": "vsc.check"}, 100, ascending=True)
        mine = [r for r in rows if r["task_id"] == job_id]
        whole = [r for r in mine if r["detail"].get("check") == "whole_system"]
        assert [r["detail"]["reason"] for r in whole] == ["whole_system:sidecar"]
        # The runner itself checked every acceptance test against the base first.
        repro = [r for r in mine if r["detail"].get("check") == "reproduction_before"]
        assert [(r["detail"]["check_id"], r["outcome"]) for r in repro] == [
            ("core-accepts-progress", "passed"),
            ("node-coder-reports-progress", "passed"),
            ("sidecar", "passed"),
        ]
        # No acceptance file reached the job branch.
        for test in tests:
            for rel in test.files:
                path = rel.split("/", 1)[1] if test.system is None else rel
                assert path not in changed, path
        per_step = {
            (s["step_id"], c["kind"], c["id"]): c["passed"]
            for s in receipt["steps"]
            for c in s["checks"]
        }
        assert per_step[("edit-core", "reproduction_after", "core-accepts-progress")]
        assert per_step[("edit-node-coder", "reproduction_after", "node-coder-reports-progress")]
        assert per_step[("edit-core", "regression", "core")]
        assert per_step[("edit-node-coder", "gate", "node-coder")]

        # The receipt verifies offline, and is anchored in the audit chain.
        assert receipt["state"] == "accepted"
        assert verify_receipt(receipt) == []
        assert verify_receipt(json.loads(json.dumps(receipt))) == []
        assert await audit.verify_chain() is None
    finally:
        await engine.dispose()

    # The real checkout was never touched.
    assert tracked_state() == real_state
