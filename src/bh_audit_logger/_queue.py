"""
Bounded async emission queue for non-blocking audit event delivery.

Events are enqueued without blocking the caller.  A single background
``asyncio.Task`` drains the queue and forwards events to the configured
sink.  When the queue is full, events are dropped and
``events_dropped_total`` is incremented.

.. note::

   This class assumes a single event loop.  Do not call ``start()`` or
   ``enqueue()`` from multiple event loops concurrently.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Literal

from bh_audit_logger._stats import AuditStats
from bh_audit_logger.sinks.base import AuditSink

_log = logging.getLogger("bh.audit.internal")


class EmitQueue:
    """Bounded async queue that decouples event building from sink I/O.

    Args:
        sink: The target audit sink.
        stats: Shared counters for emission diagnostics.
        maxsize: Maximum number of pending events (default 10 000).
        emit_failure_mode: How sink errors are handled.  ``"raise"`` is
            demoted to ``"log"`` inside the background task (logged at
            ERROR) because there is no caller to propagate to.
        failure_logger: Logger instance for internal diagnostics.
    """

    __slots__ = (
        "_sink",
        "_stats",
        "_queue",
        "_emit_failure_mode",
        "_failure_log",
        "_task",
    )

    def __init__(
        self,
        sink: AuditSink,
        stats: AuditStats,
        *,
        maxsize: int = 10_000,
        emit_failure_mode: Literal["silent", "log", "raise"] = "log",
        failure_logger: logging.Logger | None = None,
    ) -> None:
        self._sink = sink
        self._stats = stats
        self._queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue(maxsize=maxsize)
        self._emit_failure_mode = emit_failure_mode
        self._failure_log = failure_logger or _log
        self._task: asyncio.Task[None] | None = None

    @property
    def pending(self) -> int:
        """Number of events waiting to be emitted."""
        return self._queue.qsize()

    def start(self) -> None:
        """Ensure the background drain task is running.

        .. note:: Must be called from the same event loop that will run
           ``shutdown()``.  Not safe to call from multiple loops.
        """
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._drain(), name="bh-audit-emit")

    def enqueue(self, event: dict[str, Any]) -> bool:
        """Non-blocking enqueue.  Returns ``False`` if the queue is full."""
        self.start()
        try:
            self._queue.put_nowait(event)
            return True
        except asyncio.QueueFull:
            self._stats.increment("events_dropped_total")
            self._failure_log.error(
                "Audit queue full (%d), event dropped: event_id=%s",
                self._queue.maxsize,
                event.get("event_id"),
            )
            return False

    async def shutdown(self, timeout: float = 5.0) -> None:
        """Drain remaining events and stop the background task.

        On timeout, increments ``events_dropped_total`` by the number of
        events still in the queue and cancels the drain task.
        """
        if self._task is None or self._task.done():
            return
        await self._queue.put(None)
        try:
            await asyncio.wait_for(self._task, timeout=timeout)
        except TimeoutError:
            remaining = self._queue.qsize()
            self._stats.increment("events_dropped_total", remaining)
            self._failure_log.error(
                "Audit queue drain timed out after %.1fs — %d events lost",
                timeout,
                remaining,
            )
            self._task.cancel()
        self._task = None

    async def _drain(self) -> None:
        """Background loop: pull events from the queue and emit to the sink."""
        loop = asyncio.get_running_loop()
        while True:
            event = await self._queue.get()
            if event is None:
                self._queue.task_done()
                break
            try:
                await loop.run_in_executor(None, self._sink.emit, event)
            except Exception as exc:
                self._stats.increment("emit_failures_total")
                if self._emit_failure_mode == "raise":
                    self._failure_log.error(
                        "Audit sink emit failed (raise mode demoted in async queue): "
                        "event_id=%s service=%s error=%s",
                        event.get("event_id"),
                        event.get("service", {}).get("name"),
                        exc,
                    )
                elif self._emit_failure_mode == "log":
                    self._failure_log.warning(
                        "Audit sink emit failed: event_id=%s service=%s error=%s",
                        event.get("event_id"),
                        event.get("service", {}).get("name"),
                        exc,
                    )
                else:
                    self._failure_log.debug(
                        "Audit sink emit failed: event_id=%s service=%s error=%s",
                        event.get("event_id"),
                        event.get("service", {}).get("name"),
                        exc,
                    )
            else:
                self._stats.increment("events_emitted_total")
            finally:
                self._queue.task_done()
