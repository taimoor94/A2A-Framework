"""The benchmark corpus: tasks, results, and loading them.

A ``BenchTask`` is one change request with its acceptance tests and the base commits it starts
from. Two sources:

- ``estate``: the demo estate's scenarios (``examples/vsc_estate/scenarios/*.yaml``, see its
  README). ``base`` maps every system of the scenario (in the estate a system id is also its
  repository id) to ``main``: the one commit ``init_estate.py`` creates. Those commits are made
  afresh (new SHAs) each time, so the harness initialises a new estate per task and records the
  resolved SHA in the result. ``origin`` is the estate directory (holding ``init_estate.py``).
- ``history``: mined from a repository's history (``a2agw.vsc.bench.mine``); ``base`` maps the
  repository id to the parent commit and ``origin`` is the repository.

``reference_patch`` is one unified diff whose paths start with the repository id
(``a/orders-api/app.py``); bench ``oracle`` mode applies it to validate the task.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

from a2agw.vsc.spec import AcceptanceTest

__all__ = [
    "ESTATE_DIR",
    "BenchResult",
    "BenchTask",
    "FailureClass",
    "Mode",
    "load_corpus",
    "load_estate",
    "save_tasks",
    "split_patch",
]

_FORBID = ConfigDict(extra="forbid")
# examples/vsc_estate of the source checkout this package runs from.
ESTATE_DIR = Path(__file__).resolve().parents[4] / "examples" / "vsc_estate"

Mode = Literal["single", "vsc", "oracle"]
FailureClass = Literal[
    "none", "missed_system", "wrong_behaviour", "timeout", "budget", "worker_error"
]


class BenchTask(BaseModel):
    model_config = _FORBID
    id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    source: Literal["estate", "history"]
    request: str
    systems: list[str] = Field(min_length=1)
    base: dict[str, str]  # repository id -> commit (or ref)
    acceptance: list[AcceptanceTest]
    reference_patch: str | None = None
    origin: str  # the estate directory, or the mined repository


class BenchResult(BaseModel):
    model_config = _FORBID
    task_id: str
    mode: Mode
    solved: bool
    tokens: int = 0
    cost: float = 0.0
    wall_s: float = 0.0
    failure_class: FailureClass = "none"
    reason: str = ""  # the failing check ("kind:id: why") or the job's failure reason
    budget_tokens: int | None = None  # the token budget the run had
    base: dict[str, str] = Field(default_factory=dict)  # repository id -> resolved commit
    layout: list[str] = Field(default_factory=list)  # single: the workspace's sub-directories
    checks: list[dict[str, object]] = Field(default_factory=list)  # kind, id, passed, reason
    receipt_problems: list[str] = Field(default_factory=list)  # vsc: verify_receipt


def load_estate(estate_dir: Path = ESTATE_DIR) -> list[BenchTask]:
    """The estate's scenarios as tasks, sorted by id."""
    estate_dir = Path(estate_dir).resolve()
    tasks: list[BenchTask] = []
    for path in sorted((estate_dir / "scenarios").glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError(f"{path}: not a scenario")  # noqa: TRY004
        tasks.append(
            BenchTask(
                id=data["id"],
                source="estate",
                request=data["request"],
                systems=list(data["systems"]),
                base={sid: "main" for sid in data["systems"]},
                acceptance=[AcceptanceTest.model_validate(t) for t in data["acceptance"]],
                reference_patch=data.get("reference_patch"),
                origin=str(estate_dir),
            )
        )
    return tasks


def load_corpus(corpus: str | Path) -> list[BenchTask]:
    """``estate`` (the demo estate), an estate directory (``scenarios/`` plus
    ``init_estate.py``), or a directory of task files (``*.json``, as ``bench mine`` writes)."""
    if str(corpus) == "estate":
        return load_estate()
    path = Path(corpus)
    if (path / "scenarios").is_dir() and (path / "init_estate.py").is_file():
        return load_estate(path)
    if not path.is_dir():
        raise ValueError(f"corpus {corpus}: not 'estate' or a directory")
    files = sorted(path.glob("*.json"))
    if not files:
        raise ValueError(f"corpus {corpus}: no task files (*.json)")
    return [BenchTask.model_validate_json(f.read_text(encoding="utf-8")) for f in files]


def save_tasks(tasks: list[BenchTask], out: Path) -> list[Path]:
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    paths = []
    for task in tasks:
        p = out / f"{task.id}.json"
        p.write_text(task.model_dump_json(indent=2) + "\n", encoding="utf-8")
        paths.append(p)
    return paths


_HEADER = re.compile(r"^diff --git a/(\S+) b/(\S+)$", re.MULTILINE)


def split_patch(patch: str, repos: set[str] | None = None) -> dict[str, str]:
    """A repository-id-prefixed patch cut into one diff per repository id (apply each inside
    its repository with ``git apply -p2``)."""
    starts = [m.start() for m in _HEADER.finditer(patch)]
    if not starts or patch[: starts[0]].strip():
        raise ValueError("reference_patch must start with a 'diff --git' header")
    out: dict[str, str] = {}
    for start, end in zip(starts, [*starts[1:], len(patch)], strict=True):
        chunk = patch[start:end]
        m = _HEADER.match(chunk)
        assert m is not None
        repo_a, repo_b = m.group(1).split("/", 1)[0], m.group(2).split("/", 1)[0]
        if repo_a != repo_b or (repos is not None and repo_a not in repos):
            raise ValueError(f"patch path outside the task's repositories: {m.group(0)}")
        out[repo_a] = out.get(repo_a, "") + chunk
    return out
