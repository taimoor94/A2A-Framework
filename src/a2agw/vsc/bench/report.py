"""The benchmark report: ``out/report.md`` from the results of every mode.

Per mode, a table (tasks, solved, solve rate, mean tokens, mean cost, mean wall time) and the
failure-class breakdown; then one "matched budget" line comparing ``vsc`` and ``single`` on the
tasks both ran (``single``'s token budget is the ``vsc`` run's recorded tokens).
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import get_args

from a2agw.vsc.bench.corpus import BenchResult, FailureClass, Mode

__all__ = ["load_results", "matched_budget_line", "report"]

_MODES: tuple[str, ...] = get_args(Mode)
_ORDER = ("vsc", "single", "oracle")


def load_results(out: Path) -> list[BenchResult]:
    """Every ``out/<mode>/*.json`` result."""
    results: list[BenchResult] = []
    for mode in _ORDER:
        for path in sorted((Path(out) / mode).glob("*.json")):
            results.append(BenchResult.model_validate_json(path.read_text(encoding="utf-8")))
    return results


def _mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _pct(n: int, total: int) -> str:
    return f"{100.0 * n / total:.1f}%" if total else "n/a"


def matched_budget_line(results: Iterable[BenchResult]) -> str:
    """vsc against single on the tasks where single's token budget was exactly the vsc run's
    recorded tokens; tasks both modes ran with another budget are counted and named."""
    by_mode: dict[str, dict[str, BenchResult]] = {}
    for r in results:
        by_mode.setdefault(r.mode, {})[r.task_id] = r
    vsc, single = by_mode.get("vsc", {}), by_mode.get("single", {})
    both = sorted(set(vsc) & set(single))
    if not both:
        return "Matched budget: no task was run in both vsc and single mode."
    matched = [t for t in both if single[t].budget_tokens == vsc[t].tokens]
    unmatched = [t for t in both if t not in matched]
    tail = (
        f" Left out, run in both modes with a different budget: {len(unmatched)} "
        f"({', '.join(unmatched)})."
        if unmatched
        else ""
    )
    if not matched:
        return (
            "Matched budget: no task ran in single mode with vsc's recorded tokens as its budget."
            + tail
        )
    n = len(matched)
    v = sum(vsc[t].solved for t in matched)
    s = sum(single[t].solved for t in matched)
    vt = _mean([vsc[t].tokens for t in matched])
    st = _mean([single[t].tokens for t in matched])
    return (
        f"Matched budget: on {n} task{'s' if n != 1 else ''} where single's token budget equalled "
        f"vsc's recorded tokens, vsc solved {v}/{n} ({_pct(v, n)}) and single solved {s}/{n} "
        f"({_pct(s, n)}) (mean tokens: vsc {vt:.0f}, single {st:.0f})." + tail
    )


METHOD = (
    "Method overrides (identical for every task): both modes are told the affected-repository "
    "set (the task's systems); in vsc mode privileged steps are removed from the plan and the "
    "task's acceptance tests and budget replace the ones intake produced (the planner sees the "
    "acceptance tests' names, never their contents); single is unconfined in one workspace "
    "holding every repository; single's token budget is the vsc run's recorded tokens "
    "(planner and workers) for the task."
)


def report(results: Iterable[BenchResult], out: Path) -> str:
    """The Markdown report, also written to ``out/report.md``."""
    items = list(results)
    lines = ["# VSC benchmark report", "", METHOD, ""]
    classes: tuple[str, ...] = get_args(FailureClass)
    for mode in [m for m in _ORDER if m in _MODES]:
        rs = [r for r in items if r.mode == mode]
        if not rs:
            continue
        solved = sum(r.solved for r in rs)
        lines += [
            f"## Mode `{mode}`",
            "",
            "| tasks | solved | solve rate | mean tokens | mean cost (USD) | mean wall (s) |",
            "| ---: | ---: | ---: | ---: | ---: | ---: |",
            (
                f"| {len(rs)} | {solved} | {_pct(solved, len(rs))} "
                f"| {_mean([r.tokens for r in rs]):.0f} | {_mean([r.cost for r in rs]):.4f} "
                f"| {_mean([r.wall_s for r in rs]):.1f} |"
            ),
            "",
            "| failure class | tasks |",
            "| --- | ---: |",
        ]
        lines += [f"| {c} | {sum(r.failure_class == c for r in rs)} |" for c in classes]
        lines.append("")
    lines += ["## Matched budget", "", matched_budget_line(items), ""]
    text = "\n".join(lines)
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.md").write_text(text, encoding="utf-8")
    return text
