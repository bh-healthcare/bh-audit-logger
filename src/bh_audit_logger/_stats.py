"""
Internal counters for audit event emission diagnostics.
"""

from __future__ import annotations

import threading
from typing import Literal

_CounterName = Literal[
    "events_emitted_total",
    "emit_failures_total",
    "events_dropped_total",
    "validation_failures_total",
]


class AuditStats:
    """Lightweight, thread-safe counters tracking audit emission health.

    All counters are monotonically increasing integers.  Use ``snapshot()``
    to obtain a read-only dict copy suitable for health-check endpoints
    or operational dashboards.

    Counter values are read-only via properties; mutation is only possible
    through ``increment()``.
    """

    __slots__ = ("_lock", "_counters")

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, int] = {
            "events_emitted_total": 0,
            "emit_failures_total": 0,
            "events_dropped_total": 0,
            "validation_failures_total": 0,
        }

    def increment(self, name: _CounterName, amount: int = 1) -> None:
        """Atomically increment a named counter.  *amount* must be positive."""
        if amount < 0:
            raise ValueError(f"amount must be non-negative, got {amount}")
        with self._lock:
            self._counters[name] += amount

    def snapshot(self) -> dict[str, int]:
        """Return a plain-dict copy of the current counter values."""
        with self._lock:
            return dict(self._counters)

    @property
    def events_emitted_total(self) -> int:
        return self._counters["events_emitted_total"]

    @property
    def emit_failures_total(self) -> int:
        return self._counters["emit_failures_total"]

    @property
    def events_dropped_total(self) -> int:
        return self._counters["events_dropped_total"]

    @property
    def validation_failures_total(self) -> int:
        return self._counters["validation_failures_total"]
