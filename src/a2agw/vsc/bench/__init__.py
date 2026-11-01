"""The VSC benchmark: a corpus of change tasks (the demo estate's scenarios, or tasks mined
from a repository's history), a harness that runs them in ``vsc``, ``single`` (one agent, one
workspace, matched token budget) or ``oracle`` (reference patch) mode, and a Markdown report."""

from a2agw.vsc.bench.corpus import (
    ESTATE_DIR,
    BenchResult,
    BenchTask,
    load_corpus,
    load_estate,
    save_tasks,
)
from a2agw.vsc.bench.mine import amine_history, mine_history
from a2agw.vsc.bench.report import load_results, report
from a2agw.vsc.bench.run import run_bench

__all__ = [
    "ESTATE_DIR",
    "BenchResult",
    "BenchTask",
    "amine_history",
    "load_corpus",
    "load_estate",
    "load_results",
    "mine_history",
    "report",
    "run_bench",
    "save_tasks",
]
