"""In-process gateway metrics: rolling per-partner call stats, task transitions, hop depth.

The recorder keeps bounded rings of recent samples (identifiers, states and durations only,
never principals or message text). ``snapshot`` summarises the last ``window_s`` seconds;
the control-plane connector sends it in its health reports. When an OpenTelemetry
``MeterProvider`` is configured the same records also feed the ``a2agw.*`` instruments.
"""

from __future__ import annotations

import math
import time
from collections import OrderedDict, deque
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from opentelemetry.metrics import Meter

    from a2agw.serve.store import TaskIndex

ERROR_STATES = frozenset({"failed", "unavailable", "rejected"})
MAX_SAMPLES = 1024
MAX_PARTNERS_TRACKED = 512


def _percentile(values: list[float], pct: float) -> float:
    """Nearest-rank percentile; 0.0 for no samples."""
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = max(1, math.ceil(pct / 100 * len(ordered)))
    return ordered[min(rank, len(ordered)) - 1]


class _Ring:
    """Recent ``(time, duration_ms, is_error)`` samples, bounded in count."""

    def __init__(self) -> None:
        self.samples: deque[tuple[float, float, bool]] = deque(maxlen=MAX_SAMPLES)

    def add(self, now: float, duration_ms: float, error: bool) -> None:
        self.samples.append((now, duration_ms, error))

    def summary(self, cutoff: float) -> tuple[int, int, list[float]]:
        live = [s for s in self.samples if s[0] >= cutoff]
        return len(live), sum(1 for s in live if s[2]), [s[1] for s in live]


def _touch(table: OrderedDict[Any, _Ring], key: Any, max_keys: int) -> _Ring:
    ring = table.get(key)
    if ring is None:
        ring = table[key] = _Ring()
        while len(table) > max_keys:
            table.popitem(last=False)
    else:
        table.move_to_end(key)
    return ring


class GatewayMetrics:
    def __init__(
        self,
        clock: Callable[[], float] = time.monotonic,
        window_s: float = 300,
        *,
        max_partners_tracked: int = MAX_PARTNERS_TRACKED,
        meter: Meter | None = None,
        otel: bool = True,
    ) -> None:
        self._clock = clock
        self.window_s = window_s
        self._max = max_partners_tracked
        self._partners: OrderedDict[str, _Ring] = OrderedDict()
        self._edges: OrderedDict[tuple[str, str], _Ring] = OrderedDict()
        self._hops: deque[tuple[float, int]] = deque(maxlen=MAX_SAMPLES)
        # Set by the host: ``PartnerClient.partner_stats`` (breaker state, in-flight).
        self.partner_stats: Callable[[str], dict[str, Any]] | None = None
        self._calls: Any = None
        self._duration: Any = None
        self._transitions: Any = None
        if otel:
            self._init_instruments(meter)

    def _init_instruments(self, meter: Meter | None) -> None:
        if meter is None:
            from opentelemetry import metrics

            meter = metrics.get_meter("a2agw")
        self._calls = meter.create_counter("a2agw.partner.calls")
        self._duration = meter.create_histogram("a2agw.partner.duration", unit="ms")
        self._transitions = meter.create_counter("a2agw.task.transitions")

    def record_partner_call(
        self, agent_id: str, partner_id: str, state: str, duration_ms: float
    ) -> None:
        now = self._clock()
        error = state in ERROR_STATES
        _touch(self._partners, partner_id, self._max).add(now, duration_ms, error)
        _touch(self._edges, (agent_id, partner_id), self._max).add(now, duration_ms, error)
        if self._calls is not None:
            attrs = {"partner_id": partner_id, "state": state}
            self._calls.add(1, attrs)
            self._duration.record(duration_ms, attrs)

    def record_task_state(self, agent_id: str, state: str) -> None:
        if self._transitions is not None:
            self._transitions.add(1, {"agent_id": agent_id, "state": state})

    def record_hop(self, depth: int) -> None:
        self._hops.append((self._clock(), depth))

    def snapshot(self) -> dict[str, Any]:
        cutoff = self._clock() - self.window_s
        partners: dict[str, Any] = {}
        for pid, ring in self._partners.items():
            calls, errors, durations = ring.summary(cutoff)
            if not calls:
                continue
            stats = self.partner_stats(pid) if self.partner_stats is not None else {}
            partners[pid] = {
                "calls": calls,
                "errors": errors,
                "p50_ms": _percentile(durations, 50),
                "p95_ms": _percentile(durations, 95),
                "breaker": stats.get("breaker_state", "closed"),
                "in_flight": stats.get("in_flight", 0),
            }
        edges = []
        for (agent_id, pid), ring in self._edges.items():
            calls, errors, durations = ring.summary(cutoff)
            if calls:
                edges.append(
                    {
                        "from": agent_id,
                        "to": pid,
                        "calls": calls,
                        "errors": errors,
                        "p95_ms": _percentile(durations, 95),
                    }
                )
        depths = [d for t, d in self._hops if t >= cutoff]
        return {
            "window_s": self.window_s,
            "partners": partners,
            "tasks_by_state": {},
            "hop_depth": {
                "p50": int(_percentile([float(d) for d in depths], 50)),
                "max": max(depths, default=0),
            },
            "edges": edges,
        }

    async def snapshot_with_index(self, index: TaskIndex | None) -> dict[str, Any]:
        snap = self.snapshot()
        if index is not None:
            snap["tasks_by_state"] = await index.count_by_state()
        return snap
