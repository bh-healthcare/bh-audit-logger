"""
Tests for the emit() method on AuditLogger (pre-built event path).
"""

from __future__ import annotations

import pytest

from bh_audit_logger import (
    AuditLogger,
    AuditLoggerConfig,
    MemorySink,
)

from .conftest import make_test_event


@pytest.fixture
def logger_and_sink() -> tuple[AuditLogger, MemorySink]:
    sink = MemorySink()
    config = AuditLoggerConfig(
        service_name="test-service",
        service_environment="test",
        metadata_allowlist=frozenset({"safe_key"}),
    )
    logger = AuditLogger(config=config, sink=sink)
    return logger, sink


def test_emit_valid_prebuilt_event(
    logger_and_sink: tuple[AuditLogger, MemorySink],
) -> None:
    logger, sink = logger_and_sink
    event = make_test_event()
    logger.emit(event)
    assert len(sink) == 1
    assert sink.events[0]["event_id"] == event["event_id"]


def test_emit_invalid_prebuilt_event_dropped(
    logger_and_sink: tuple[AuditLogger, MemorySink],
) -> None:
    logger, sink = logger_and_sink
    event = make_test_event()
    del event["service"]
    logger.emit(event)
    assert len(sink) == 0
    assert logger.stats.validation_failures_total >= 1
    assert logger.stats.events_dropped_total >= 1


def test_emit_applies_metadata_allowlist(
    logger_and_sink: tuple[AuditLogger, MemorySink],
) -> None:
    logger, sink = logger_and_sink
    event = make_test_event(metadata={"safe_key": "ok", "forbidden": "nope"})
    logger.emit(event)
    assert len(sink) == 1
    emitted = sink.events[0]
    assert "safe_key" in emitted["metadata"]
    assert "forbidden" not in emitted["metadata"]


def test_emit_applies_error_sanitization(
    logger_and_sink: tuple[AuditLogger, MemorySink],
) -> None:
    logger, sink = logger_and_sink
    event = make_test_event(
        outcome={
            "status": "FAILURE",
            "error_type": "ApplicationError",
            "error_message": "SSN 123-45-6789 leaked",
        }
    )
    logger.emit(event)
    assert len(sink) == 1
    msg = sink.events[0]["outcome"]["error_message"]
    assert "123-45-6789" not in msg


@pytest.mark.skipif(
    not pytest.importorskip("jsonschema", reason="needs jsonschema"),
    reason="jsonschema not installed",
)
def test_emit_with_validation_enabled() -> None:
    sink = MemorySink()
    config = AuditLoggerConfig(
        service_name="test-service",
        service_environment="test",
        validate_events=True,
        validation_failure_mode="drop",
    )
    logger = AuditLogger(config=config, sink=sink)
    event = make_test_event()
    logger.emit(event)
    assert len(sink) == 1


def test_emit_returns_none(
    logger_and_sink: tuple[AuditLogger, MemorySink],
) -> None:
    logger, sink = logger_and_sink
    result = logger.emit(make_test_event())
    assert result is None
