"""The benchmark: history mining, the three modes and the report.

Real models never run here: ``vsc`` mode uses a scripted planner whose steps carry the reference
solution as files for the fake ``apply`` worker (``worker_agent.py``), and ``single`` mode hands
the same files to the worker through the ``single_prompt`` hook. The post-patch file contents
are computed by applying the task's reference patch to a scratch copy.
"""

from __future__ import annotations

import dataclasses
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from a2agw.vsc.bench import (
    BenchResult,
    BenchTask,
    amine_history,
    load_corpus,
    load_estate,
    load_results,
    mine_history,
    report,
    run_bench,
    save_tasks,
)
from a2agw.vsc.bench.corpus import split_patch
from a2agw.vsc.bench.mine import restrict_command
from a2agw.vsc.bench.report import matched_budget_line
from a2agw.vsc.bench.run import classify
from a2agw.vsc.config import BudgetConfig, CheckConfig, SystemConfig, VscConfig
from a2agw.vsc.plan import Plan, PlanStep
from a2agw.vsc.planner import ScriptedPlanner

from .conftest import worker
from .estate_support import ESTATE_DIR, estate_config

PY = sys.executable
# plain pytest (no plugins of this environment): fast startup
PYTEST = [
    PY,
    "-B",
    "-m",
    "pytest",
    "-q",
    "-p",
    "no:cacheprovider",
    "--disable-plugin-autoload",
    "tests",
]
BUDGET = BudgetConfig(attempts=2, deadline_s=600)


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True, text=True
    ).stdout.strip()


def write(root: Path, files: dict[str, str]) -> None:
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)


def commit(repo: Path, message: str, files: dict[str, str]) -> str:
    write(repo, files)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", message)
    return git(repo, "rev-parse", "HEAD")


def test_fn(name: str, value: int) -> str:
    return f"from lib import {name}\n\n\ndef test_{name}():\n    assert {name}() == {value}\n"


test_fn.__test__ = False  # a helper, not a test


def lib(*names: tuple[str, int]) -> str:
    return "".join(f"def {n}():\n    return {v}\n\n\n" for n, v in names)


@pytest.fixture
def mono(tmp_path):
    """One repository, two systems (``a/`` and ``b/``), crafted history:

    1. initial (root: never a task)
    2. a only, with a test (one system)
    3. a and b with new failing tests            -> task
    4. a and b, no new tests                     (no acceptance)
    5. a and b, new test passing on the parent   (dropped by reproduction_before)
    5b. a and b, new test failing at the commit too (dropped: not solvable)
    6. merge --no-ff of a side branch changing a and b with new failing tests -> task (the
       side branch's own commit is not on the first-parent line)
    """
    repo = tmp_path / "mono"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "user.name", "T")
    git(repo, "config", "user.email", "t@example.invalid")
    shas = {}
    shas["initial"] = commit(
        repo,
        "initial",
        {
            "a/lib.py": lib(("f", 1)),
            "a/tests/test_lib.py": test_fn("f", 1),
            "b/lib.py": lib(("f", 1)),
            "b/tests/test_lib.py": test_fn("f", 1),
        },
    )
    shas["a-only"] = commit(
        repo, "a only", {"a/lib.py": lib(("f", 1), ("e", 5)), "a/tests/test_e.py": test_fn("e", 5)}
    )
    shas["cross"] = commit(
        repo,
        "Add g to a and h to b\n\nBoth services grow a function; the tests pin them.",
        {
            "a/lib.py": lib(("f", 1), ("e", 5), ("g", 2)),
            "b/lib.py": lib(("f", 1), ("h", 3)),
            "a/tests/test_g.py": test_fn("g", 2),
            "b/tests/test_h.py": test_fn("h", 3),
        },
    )
    shas["no-tests"] = commit(repo, "touch both", {"a/notes.txt": "a\n", "b/notes.txt": "b\n"})
    shas["passing"] = commit(
        repo,
        "a test that already passes",
        {"a/tests/test_more_f.py": test_fn("f", 1), "b/notes.txt": "b2\n"},
    )
    shas["broken"] = commit(  # fails on the parent AND at the commit: unsolvable, dropped
        repo,
        "a test that never passes",
        {"a/tests/test_bad.py": test_fn("f", 99), "b/notes.txt": "b3\n"},
    )
    git(repo, "rm", "-q", "a/tests/test_bad.py")
    git(repo, "commit", "-q", "-m", "drop the bad test")  # one system: not a task
    git(repo, "checkout", "-q", "-b", "side")
    commit(
        repo,
        "side work",
        {
            "a/lib.py": lib(("f", 1), ("e", 5), ("g", 2), ("k", 7)),
            "b/lib.py": lib(("f", 1), ("h", 3), ("k", 7)),
            "a/tests/test_k.py": test_fn("k", 7),
            "b/tests/test_k.py": test_fn("k", 7),
        },
    )
    git(repo, "checkout", "-q", "main")
    git(repo, "merge", "-q", "--no-ff", "-m", "Merge side: k everywhere", "side")
    shas["merge"] = git(repo, "rev-parse", "HEAD")
    git(repo, "tag", "v-solution", shas["merge"])
    systems = [
        SystemConfig(id="svc-a", repo="./mono", path="a", tests=PYTEST),
        SystemConfig(id="svc-b", repo="./mono", path="b", tests=PYTEST),
    ]
    return repo, systems, shas


def test_restrict_command():
    assert restrict_command(PYTEST, ["tests/test_g.py"]) == [*PYTEST[:-1], "tests/test_g.py"]
    node = ["node", "--test", "test/*.test.mjs"]
    assert restrict_command(node, ["test/x.test.mjs"]) == ["node", "--test", "test/x.test.mjs"]
    # a tool whose file form is unknown keeps its command (it still runs the new files)
    assert restrict_command(["make", "check"], ["tests/t.py"]) == ["make", "check"]
    assert restrict_command(["go", "test", "./..."], ["tests/x_test.go"]) == ["go", "test", "./..."]
    assert restrict_command(["npm", "test"], ["tests/x.test.js"]) == ["npm", "test"]
    # never the value of a preceding option
    k = [PY, "-m", "pytest", "-k", "tests"]
    assert restrict_command(k, ["tests/test_g.py"]) == [*k, "tests/test_g.py"]
    # unittest discover -s tests: not "-s tests/test_g.py", but the file form
    discover = [PY, "-B", "-m", "unittest", "discover", "-s", "tests"]
    assert restrict_command(discover, ["tests/test_g.py"]) == [
        PY, "-B", "-m", "unittest", "tests/test_g.py",
    ]  # fmt: skip
    assert restrict_command([PY, "-m", "unittest", "-v"], ["tests/t.py"]) == [
        PY, "-m", "unittest", "-v", "tests/t.py",
    ]  # fmt: skip


def test_mine_history_finds_cross_system_commits(mono):
    repo, systems, shas = mono
    tasks = mine_history(repo, systems)
    assert [t.id for t in tasks] == [f"mono-{shas['merge'][:12]}", f"mono-{shas['cross'][:12]}"]
    merge, cross = tasks
    assert merge.base == {"mono": git(repo, "rev-parse", f"{shas['merge']}^1")}
    assert merge.request == "Merge side: k everywhere"
    assert cross.source == "history" and cross.origin == str(repo.resolve())
    assert cross.request == (
        "Add g to a and h to b\n\nBoth services grow a function; the tests pin them."
    )
    assert cross.systems == ["svc-a", "svc-b"]
    assert cross.base == {"mono": shas["a-only"]}
    a, b = cross.acceptance
    assert (a.id, a.system, a.check) == ("svc-a-added-tests", "svc-a", None)
    assert a.files == {"a/tests/test_g.py": test_fn("g", 2)}
    assert a.run == [*PYTEST[:-1], "tests/test_g.py"]
    assert b.files == {"b/tests/test_h.py": test_fn("h", 3)}
    assert set(split_patch(cross.reference_patch or "")) == {"mono"}
    assert "b/mono/a/lib.py" in (cross.reference_patch or "")
    # newest first, bounded
    assert [t.id for t in mine_history(repo, systems, limit=1)] == [merge.id]
    assert mine_history(repo, systems, min_systems=3) == []
    one = mine_history(repo, systems, min_systems=1)
    assert f"mono-{shas['a-only'][:12]}" in [t.id for t in one]


async def test_bench_oracle_on_mined_task_and_corpus_roundtrip(mono, tmp_path):
    repo, systems, shas = mono
    tasks = await amine_history(repo, systems, limit=1)
    corpus_dir = tmp_path / "corpus"
    save_tasks(tasks, corpus_dir)
    assert load_corpus(corpus_dir) == tasks
    cfg = VscConfig(systems=systems)
    out = tmp_path / "out"
    (result,) = await run_bench(
        tasks, mode="oracle", cfg=cfg, budget=BUDGET, out=out, config_dir=tmp_path
    )
    assert result.solved, result
    assert result.base == tasks[0].base
    kinds = [c["kind"] for c in result.checks]
    assert kinds.count("reproduction_after") == 2 and kinds.count("regression") == 2
    assert load_results(out) == [result]
    assert git(repo, "rev-parse", "main") == shas["merge"]  # the origin is never touched


# -- a tiny two-repository estate -------------------------------------------------------------

GREET = "def hello():\n    return 'hi'\n"
TEST_X = (
    "import unittest\n\nfrom greet import hello\n\n\n"
    "class T(unittest.TestCase):\n    def test_hello(self):\n"
    "        self.assertEqual(hello(), 'hi')\n"
)
UNITTEST = [PY, "-B", "-m", "unittest", "discover", "-s", "tests"]
WHOLE = [
    PY,
    "-c",
    (
        "import os, sys; ok = all(os.path.exists(os.path.join(os.environ[k], 'greet.py'))"
        " for k in ('VSC_WS_ALPHA', 'VSC_WS_BETA')) and os.path.exists(os.path.join("
        "os.environ['VSC_WS_ALPHA'], 'e2e', 'marker.txt')); sys.exit(0 if ok else 1)"
    ),
]
INIT = """\
import subprocess, sys
from pathlib import Path

FILES = {files!r}
target = Path(sys.argv[1])
for name, files in FILES.items():
    repo = target / name
    for rel, content in files.items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(content)
    for args in (["init", "-q", "-b", "main"], ["add", "-A"],
                 ["-c", "user.name=E", "-c", "user.email=e@example.invalid",
                  "commit", "-q", "-m", "initial"]):
        subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)
"""
PATCH = """\
diff --git a/alpha/greet.py b/alpha/greet.py
new file mode 100644
--- /dev/null
+++ b/alpha/greet.py
@@ -0,0 +1,2 @@
+def hello():
+    return 'hi'
diff --git a/beta/greet.py b/beta/greet.py
new file mode 100644
--- /dev/null
+++ b/beta/greet.py
@@ -0,0 +1,2 @@
+def hello():
+    return 'hi'
"""
SOLUTION = {"alpha": {"greet.py": GREET}, "beta": {"greet.py": GREET}}


@pytest.fixture
def tiny(tmp_path):
    """An estate directory (``init_estate.py`` + ``scenarios/``) of two repositories, a config
    for it and its one task."""
    est = tmp_path / "tiny"
    repo_files = {".gitignore": "__pycache__/\n", "tests/test_x.py": TEST_X}
    (est / "scenarios").mkdir(parents=True)
    (est / "init_estate.py").write_text(
        INIT.format(files={"alpha": repo_files, "beta": repo_files})
    )
    scenario = {
        "id": "greet-everywhere",
        "request": "Both services must greet: add hello() returning 'hi' to alpha and beta.",
        "systems": ["alpha", "beta"],
        "acceptance": [
            {"id": "alpha-greets", "system": "alpha", "files": {"tests/test_g.py": TEST_X}},
            {"id": "e2e", "check": "whole", "files": {"alpha/e2e/marker.txt": "e2e\n"}},
        ],
        "reference_patch": PATCH,
    }
    (est / "scenarios" / "greet-everywhere.yaml").write_text(json.dumps(scenario))
    cfg = VscConfig(
        systems=[
            SystemConfig(id="alpha", repo="./estate/alpha", tests=UNITTEST),
            SystemConfig(id="beta", repo="./estate/beta", tests=UNITTEST),
        ],
        checks=[CheckConfig(id="whole", systems=["alpha", "beta"], run=WHOLE, timeout_s=60)],
        planner="scripted",
    )
    (task,) = load_corpus(est)
    return cfg, task


def with_files(files: dict[str, str]):
    def hook(task: BenchTask, text: str) -> str:
        return text + "\n---FILES---\n" + json.dumps({"files": files})

    return hook


def prefixed(solution: dict[str, dict[str, str]]) -> dict[str, str]:
    return {f"{rid}/{rel}": c for rid, files in solution.items() for rel, c in files.items()}


class FilesPlanner(ScriptedPlanner):
    """One edit step per system whose instructions carry that repository's solution files for
    the fake ``apply`` worker; ``after`` lists systems whose step runs last."""

    def __init__(self, solution: dict[str, dict[str, str]], after: tuple[str, ...] = ()) -> None:
        super().__init__()
        self._solution = solution
        self._after = after

    async def plan(self, spec):
        first = [s for s in spec.systems if s not in self._after]

        def step(sid: str) -> PlanStep:
            files = json.dumps({"files": self._solution.get(sid, {})})
            return PlanStep(
                id=f"edit-{sid}",
                system=sid,
                depends_on=[f"edit-{d}" for d in first] if sid in self._after else [],
                instructions=f"{spec.done}\n---FILES---\n{files}",
            )

        return Plan(steps=[step(s) for s in spec.systems])


def test_load_estate_corpus():
    tasks = load_estate()
    assert len(tasks) >= 10 and all(t.source == "estate" and t.reference_patch for t in tasks)
    t = next(t for t in tasks if t.id == "release-stock-on-cancel")
    assert t.base == {s: "main" for s in t.systems} and t.origin == str(ESTATE_DIR)
    assert any(a.system is None and a.check == "estate" for a in t.acceptance)


async def test_bench_single_mode_one_workspace(tiny, tmp_path):
    cfg, task = tiny
    out = tmp_path / "out"
    (out / "vsc").mkdir(parents=True)
    vsc = BenchResult(task_id=task.id, mode="vsc", solved=True, tokens=1234)
    (out / "vsc" / f"{task.id}.json").write_text(vsc.model_dump_json())
    (r,) = await run_bench(
        [task], mode="single", cfg=cfg, budget=BUDGET, out=out, config_dir=tmp_path,
        workers=[worker("apply")], single_prompt=with_files(prefixed(SOLUTION)),
    )  # fmt: skip
    assert r.solved, r
    assert r.layout == ["alpha", "beta"]  # one workspace, every repository a sub-directory
    assert r.budget_tokens == 1234  # matched to the vsc run's recorded tokens
    assert set(r.base) == {"alpha", "beta"} and all(len(v) == 40 for v in r.base.values())
    kinds = [(c["kind"], c["id"]) for c in r.checks]
    assert ("reproduction_after", "alpha-greets") in kinds
    assert ("regression", "alpha") in kinds and ("regression", "beta") in kinds
    assert kinds[-1] == ("whole_system", "whole")
    assert BenchResult.model_validate_json((out / "single" / f"{task.id}.json").read_text()) == r


async def test_bench_single_mode_failure_classes(tiny, tmp_path):
    cfg, task = tiny
    out = tmp_path / "out"
    (missed,) = await run_bench(
        [task], mode="single", cfg=cfg, budget=BUDGET, out=out, config_dir=tmp_path,
        workers=[worker("apply")], single_prompt=with_files({"alpha/greet.py": GREET}),
    )  # fmt: skip
    assert (missed.solved, missed.failure_class) == (False, "missed_system"), missed
    assert missed.budget_tokens == BUDGET.tokens  # no vsc result: the configured budget
    (out / "vsc").mkdir()
    (out / "vsc" / f"{task.id}.json").write_text(
        BenchResult(task_id=task.id, mode="vsc", solved=True, tokens=10).model_dump_json()
    )
    (over,) = await run_bench(
        [task], mode="single", cfg=cfg, budget=BUDGET, out=out, config_dir=tmp_path,
        workers=[worker("usage")], single_prompt=with_files(prefixed(SOLUTION)),
    )  # fmt: skip
    assert (over.solved, over.failure_class, over.tokens) == (False, "budget", 30), over


async def test_bench_oracle_and_vsc_on_tiny_estate(tiny, tmp_path):
    cfg, task = tiny
    out = tmp_path / "out"
    (oracle,) = await run_bench([task], mode="oracle", cfg=cfg, budget=BUDGET, out=out,
                                config_dir=tmp_path)  # fmt: skip
    assert oracle.solved, oracle
    (vsc,) = await run_bench(
        [task], mode="vsc", cfg=cfg, budget=BUDGET, out=out, config_dir=tmp_path,
        workers=[worker("usage")], planner_factory=lambda t: FilesPlanner(SOLUTION),
    )  # fmt: skip
    assert vsc.solved, vsc
    assert vsc.tokens == 60 and vsc.receipt_problems == []  # two steps, 30 tokens each
    (single,) = await run_bench(
        [task], mode="single", cfg=cfg, budget=BUDGET, out=out, config_dir=tmp_path,
        workers=[worker("usage")], single_prompt=with_files(prefixed(SOLUTION)),
    )  # fmt: skip
    assert single.solved and single.budget_tokens == 60, single
    text = report(load_results(out), out)
    assert (
        "on 1 task where single's token budget equalled vsc's recorded tokens, vsc solved 1/1"
        in text
    )


async def test_bench_vsc_wrong_behaviour(tiny, tmp_path):
    cfg, task = tiny
    wrong = {"alpha": {"greet.py": "def hello():\n    return 'no'\n"}, "beta": {"greet.py": GREET}}
    (r,) = await run_bench(
        [task], mode="vsc", cfg=cfg, budget=BUDGET, out=tmp_path / "out", config_dir=tmp_path,
        workers=[worker("apply")], planner_factory=lambda t: FilesPlanner(wrong),
    )  # fmt: skip
    assert (r.solved, r.failure_class) == (False, "wrong_behaviour"), r
    assert r.reason.startswith("reproduction_after:alpha-greets"), r.reason


def test_classify():
    assert classify(solved=True, kind=None) == "none"
    assert classify(solved=False, kind="regression", reason="timeout") == "timeout"
    assert classify(solved=False, kind=None, limit="deadline") == "timeout"
    assert classify(solved=False, kind=None, limit="tokens") == "budget"
    assert classify(solved=False, kind="worker") == "worker_error"
    assert classify(solved=False, kind="whole_system", missed=True) == "missed_system"
    assert classify(solved=False, kind="regression") == "wrong_behaviour"


def test_bench_report_matched_budget_line(tmp_path):
    def r(task, mode, solved, tokens, fc="none", budget=None):
        return BenchResult(task_id=task, mode=mode, solved=solved, tokens=tokens, cost=0.5,
                           wall_s=2.0, failure_class=fc, budget_tokens=budget)  # fmt: skip

    results = [
        r("t1", "vsc", True, 1000),
        r("t2", "vsc", True, 3000),
        r("t3", "vsc", False, 500, "budget"),
        r("t4", "vsc", True, 700),
        r("t1", "single", True, 900, budget=1000),
        r("t2", "single", False, 3000, "missed_system", budget=3000),
        r("t4", "single", True, 650, budget=2_000_000),  # single ran before vsc: not matched
        r("t9", "single", False, 100, "worker_error", budget=5),  # vsc never ran it
        r("t1", "oracle", True, 0),
    ]
    text = report(results, tmp_path)
    assert (tmp_path / "report.md").read_text() == text
    line = (
        "Matched budget: on 2 tasks where single's token budget equalled vsc's recorded tokens, "
        "vsc solved 2/2 (100.0%) and single solved 1/2 (50.0%) (mean tokens: vsc 2000, single "
        "1950). Left out, run in both modes with a different budget: 1 (t4)."
    )
    assert line in text.splitlines()
    assert "## Mode `vsc`" in text and "## Mode `single`" in text and "## Mode `oracle`" in text
    assert "| 4 | 3 | 75.0% | 1300 | 0.5000 | 2.0 |" in text
    for override in (
        "told the affected-repository set",
        "privileged steps are removed",
        "acceptance tests and budget replace",
        "single is unconfined",
    ):
        assert override in text, override
    assert "| missed_system | 1 |" in text
    assert matched_budget_line([results[0]]) == (
        "Matched budget: no task was run in both vsc and single mode."
    )
    only_unmatched = matched_budget_line([results[3], results[6]])
    assert only_unmatched == (
        "Matched budget: no task ran in single mode with vsc's recorded tokens as its budget. "
        "Left out, run in both modes with a different budget: 1 (t4)."
    )


# -- the real demo estate (one scenario) -------------------------------------------------------

ESTATE_TASK = "release-stock-on-cancel"
needs_node = pytest.mark.skipif(shutil.which("node") is None, reason="node is not on PATH")


def post_patch_files(task: BenchTask, tmp: Path) -> dict[str, dict[str, str]]:
    """Per repository, the content of every file the reference patch adds or changes."""
    from .estate_support import apply_patch, init_estate

    assert init_estate(tmp / "estate").returncode == 0
    repos = {rid: tmp / "estate" / rid for rid in task.systems}
    apply_patch(task.reference_patch or "", repos)
    out: dict[str, dict[str, str]] = {}
    for rid, repo in repos.items():
        git(repo, "add", "-A")
        names = git(repo, "diff", "--cached", "--name-only", "--diff-filter=AM").splitlines()
        out[rid] = {n: (repo / n).read_text() for n in names}
    return out


@pytest.mark.estate
@needs_node
async def test_bench_estate_scenario_oracle_and_vsc(tmp_path):
    (task,) = [t for t in load_estate() if t.id == ESTATE_TASK]
    cfg = estate_config(ESTATE_DIR / "estate")  # repositories are re-pointed per task
    out = tmp_path / "out"
    (oracle,) = await run_bench([task], mode="oracle", cfg=cfg, budget=BUDGET, out=out,
                                config_dir=tmp_path)  # fmt: skip
    assert oracle.solved, oracle
    assert ("whole_system", "estate") == (oracle.checks[-1]["kind"], oracle.checks[-1]["id"])
    solution = post_patch_files(task, tmp_path / "scratch")
    fake = dataclasses.replace(worker("apply"), timeout_s=120)
    (vsc,) = await run_bench(
        [task], mode="vsc", cfg=cfg, budget=BUDGET, out=out, config_dir=tmp_path,
        workers=[fake], planner_factory=lambda t: FilesPlanner(solution, after=("contract",)),
    )  # fmt: skip
    assert vsc.solved, vsc
    assert vsc.receipt_problems == []
    assert (vsc.checks[-1]["kind"], vsc.checks[-1]["id"]) == ("whole_system", "estate")


def test_cli_bench_mine_run_report(mono, tmp_path):
    from typer.testing import CliRunner

    from a2agw import cli

    repo, systems, shas = mono
    config = tmp_path / "a2agw.yaml"
    config.write_text(
        json.dumps(
            {
                "base_url": "http://t",
                "vsc": {"systems": [s.model_dump() for s in systems], "planner": "scripted"},
            }
        )
    )
    runner = CliRunner()
    corpus, out = tmp_path / "corpus", tmp_path / "out"
    res = runner.invoke(
        cli.app,
        ["vsc", "bench", "mine", str(repo), "--out", str(corpus), "--config", str(config),
         "--limit", "1"],
    )  # fmt: skip
    assert res.exit_code == 0, res.output
    assert f"mono-{shas['merge'][:12]}" in res.output
    res = runner.invoke(
        cli.app,
        ["vsc", "bench", "run", "--corpus", str(corpus), "--mode", "oracle", "--out", str(out),
         "--config", str(config)],
    )  # fmt: skip
    assert res.exit_code == 0, res.output
    assert "1/1 solved" in res.output
    res = runner.invoke(cli.app, ["vsc", "bench", "report", str(out)])
    assert res.exit_code == 0, res.output
    assert "## Mode `oracle`" in res.output and (out / "report.md").is_file()
    res = runner.invoke(
        cli.app,
        ["vsc", "bench", "run", "--corpus", str(corpus), "--mode", "vsc", "--out", str(out),
         "--config", str(config)],
    )  # fmt: skip
    assert res.exit_code == 1 and "needs at least one worker" in res.output


def test_prepared_history_repo_has_no_solution(mono, tmp_path):
    """The task's repository holds the base and its ancestry only: not the solution commit, no
    tags, no reflog, no other branch."""
    from a2agw.vsc.bench.run import _prepare

    repo, systems, shas = mono
    (task,) = mine_history(repo, systems, limit=1)  # the merge commit's task
    cfg = VscConfig(systems=systems)
    tmp = tmp_path / "prep"
    tmp.mkdir()
    tcfg, base = _prepare(task, cfg, tmp_path, tmp)
    prepared = Path(tcfg.systems[0].repo)
    assert base == task.base
    assert git(prepared, "rev-parse", "HEAD") == task.base["mono"]
    for sha in (shas["merge"], git(repo, "rev-parse", "side")):
        res = subprocess.run(
            ["git", "cat-file", "-e", sha], cwd=prepared, capture_output=True, check=False
        )
        assert res.returncode != 0, sha
    assert git(prepared, "tag") == ""
    assert git(prepared, "remote") == ""
    assert git(prepared, "for-each-ref", "--format=%(refname)") == "refs/heads/main"
    assert shas["merge"] not in git(prepared, "log", "--all", "--format=%H")
    assert git(prepared, "reflog", "--all") == ""
