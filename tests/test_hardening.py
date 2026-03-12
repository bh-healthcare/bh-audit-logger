"""
Tests for v0.2.0 production hardening.

Covers sink failure isolation, metadata safety, internal counters,
and compact failure logging.
"""

from __future__ import annotations

import logging
from typing import Any

import pytest

from bh_audit_logger import AuditLogger, AuditLoggerConfig, MemorySink


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _ExplodingSink:
    """A sink that always raises on emit."""

    def emit(self, event: dict[str, Any]) -> None:
        raise RuntimeError("boom")


_FIXED_EVENT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def _make_logger(
    sink: Any = None,
    *,
    emit_failure_mode: str = "log",
    metadata_allowlist: set[str] | None = None,
    max_metadata_value_length: int = 200,
) -> AuditLogger:
    cfg = AuditLoggerConfig(
        service_name="hardening-test",
        service_environment="test",
        emit_failure_mode=emit_failure_mode,  # type: ignore[arg-type]
        metadata_allowlist=metadata_allowlist or set(),
        max_metadata_value_length=max_metadata_value_length,
        id_factory=lambda: _FIXED_EVENT_ID,
    )
    return AuditLogger(config=cfg, sink=sink or MemorySink())


# ---------------------------------------------------------------------------
# Sink failure isolation
# ---------------------------------------------------------------------------

class TestSinkFailureIsolation:
    """Sink errors must not break caller logic by default."""

    def test_silent_mode_swallows_exception(self) -> None:
        logger = _make_logger(_ExplodingSink(), emit_failure_mode="silent")
        event = logger.audit("READ", resource={"type": "Patient"})
        assert event["event_id"] == _FIXED_EVENT_ID

    def test_log_mode_swallows_exception(self) -> None:
        logger = _make_logger(_ExplodingSink(), emit_failure_mode="log")
        event = logger.audit("READ", resource={"type": "Patient"})
        assert event["event_id"] == _FIXED_EVENT_ID

    def test_raise_mode_propagates_exception(self) -> None:
        logger = _make_logger(_ExplodingSink(), emit_failure_mode="raise")
        with pytest.raises(RuntimeError, match="boom"):
            logger.audit("READ", resource={"type": "Patient"})

    def test_original_exception_not_masked(self) -> None:
        """raise mode must re-raise the original exception type, not a wrapper."""

        class _TypeErrorSink:
            def emit(self, event: dict[str, Any]) -> None:
                raise TypeError("bad type")

        logger = _make_logger(_TypeErrorSink(), emit_failure_mode="raise")
        with pytest.raises(TypeError, match="bad type"):
            logger.audit("READ", resource={"type": "Patient"})


# ---------------------------------------------------------------------------
# Internal counters
# ---------------------------------------------------------------------------

class TestCounters:
    """AuditStats counters must increment correctly."""

    def test_events_emitted_increments(self) -> None:
        logger = _make_logger()
        logger.audit("READ", resource={"type": "Patient"})
        logger.audit("CREATE", resource={"type": "Note"})
        assert logger.stats.events_emitted_total == 2

    def test_emit_failures_increments(self) -> None:
        logger = _make_logger(_ExplodingSink(), emit_failure_mode="log")
        logger.audit("READ", resource={"type": "Patient"})
        assert logger.stats.emit_failures_total == 1
        assert logger.stats.events_emitted_total == 0

    def test_snapshot_returns_dict_copy(self) -> None:
        logger = _make_logger()
        logger.audit("READ", resource={"type": "Patient"})
        snap = logger.stats.snapshot()
        assert snap["events_emitted_total"] == 1
        assert isinstance(snap, dict)


# ---------------------------------------------------------------------------
# Metadata safety
# ---------------------------------------------------------------------------

class TestMetadataSafety:
    """Metadata must drop non-scalars and truncate long strings."""

    def test_drops_non_scalar_dict(self) -> None:
        logger = _make_logger(
            metadata_allowlist={"safe", "nested"},
        )
        event = logger.audit(
            "READ",
            resource={"type": "Patient"},
            metadata={"safe": "ok", "nested": {"a": 1}},
        )
        assert event["metadata"] == {"safe": "ok"}

    def test_drops_non_scalar_list(self) -> None:
        logger = _make_logger(
            metadata_allowlist={"safe", "items"},
        )
        event = logger.audit(
            "READ",
            resource={"type": "Patient"},
            metadata={"safe": 42, "items": [1, 2, 3]},
        )
        assert event["metadata"] == {"safe": 42}

    def test_drops_non_scalar_tuple(self) -> None:
        logger = _make_logger(
            metadata_allowlist={"coords"},
        )
        event = logger.audit(
            "READ",
            resource={"type": "Patient"},
            metadata={"coords": (1, 2)},
        )
        assert "metadata" not in event

    def test_truncates_long_strings(self) -> None:
        logger = _make_logger(
            metadata_allowlist={"note"},
            max_metadata_value_length=10,
        )
        event = logger.audit(
            "READ",
            resource={"type": "Patient"},
            metadata={"note": "a" * 50},
        )
        assert event["metadata"]["note"] == "a" * 10 + "..."
        assert len(event["metadata"]["note"]) == 13

    def test_short_strings_not_truncated(self) -> None:
        logger = _make_logger(
            metadata_allowlist={"note"},
            max_metadata_value_length=100,
        )
        event = logger.audit(
            "READ",
            resource={"type": "Patient"},
            metadata={"note": "short"},
        )
        assert event["metadata"]["note"] == "short"


# ---------------------------------------------------------------------------
# Compact failure logging
# ---------------------------------------------------------------------------

class TestFailureLogging:
    """Internal failure logs must be compact and never contain full payload."""

    def test_log_contains_compact_summary(self, caplog: pytest.LogCaptureFixture) -> None:
        logger = _make_logger(_ExplodingSink(), emit_failure_mode="log")
        with caplog.at_level(logging.WARNING, logger="bh.audit.internal"):
            logger.audit(
                "READ",
                resource={"type": "Patient"},
                metadata={"secret": "do-not-log-this"},
            )

        assert len(caplog.records) == 1
        msg = caplog.records[0].getMessage()
        assert _FIXED_EVENT_ID in msg
        assert "hardening-test" in msg
        assert "READ" in msg
        assert "Patient" in msg

    def test_log_does_not_contain_full_payload(self, caplog: pytest.LogCaptureFixture) -> None:
        logger = _make_logger(
            _ExplodingSink(),
            emit_failure_mode="log",
            metadata_allowlist={"secret"},
        )
        with caplog.at_level(logging.WARNING, logger="bh.audit.internal"):
            logger.audit(
                "READ",
                actor={"subject_id": "user_sensitive", "subject_type": "human"},
                resource={"type": "Patient"},
                metadata={"secret": "do-not-log-this"},
            )

        msg = caplog.records[0].getMessage()
        assert "do-not-log-this" not in msg
        assert "user_sensitive" not in msg

    def test_silent_mode_emits_no_logs(self, caplog: pytest.LogCaptureFixture) -> None:
        logger = _make_logger(_ExplodingSink(), emit_failure_mode="silent")
        with caplog.at_level(logging.DEBUG, logger="bh.audit.internal"):
            logger.audit("READ", resource={"type": "Patient"})

        assert len(caplog.records) == 0
