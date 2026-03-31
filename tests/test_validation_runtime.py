"""
Tests for runtime schema validation (_validation.py) and its integration with AuditLogger.

Requires the [jsonschema] optional extra.
"""

from __future__ import annotations

from typing import Any

import pytest

pytest.importorskip("jsonschema", reason="jsonschema required for runtime validation tests")

from bh_audit_logger import (  # noqa: E402
    AuditLogger,
    AuditLoggerConfig,
    AuditValidationError,
    MemorySink,
    validate_event_schema,
)

from .conftest import make_test_event  # noqa: E402


@pytest.fixture
def validating_config() -> AuditLoggerConfig:
    return AuditLoggerConfig(
        service_name="test-service",
        service_environment="test",
        validate_events=True,
        validation_failure_mode="drop",
    )


@pytest.fixture
def validating_logger(validating_config: AuditLoggerConfig) -> tuple[AuditLogger, MemorySink]:
    sink = MemorySink()
    logger = AuditLogger(config=validating_config, sink=sink)
    return logger, sink


def test_validate_event_schema_valid() -> None:
    event = make_test_event()
    errors = validate_event_schema(event, "1.1")
    assert errors == []


def test_validate_event_schema_invalid() -> None:
    event = make_test_event()
    del event["service"]
    errors = validate_event_schema(event, "1.1")
    assert len(errors) > 0
    assert any("service" in e for e in errors)


def test_validate_events_false_skips() -> None:
    """When validate_events=False, malformed prebuilt events still reach the sink."""
    sink = MemorySink()
    config = AuditLoggerConfig(
        service_name="test-service",
        service_environment="test",
        validate_events=False,
    )
    logger = AuditLogger(config=config, sink=sink)
    event = make_test_event()
    event["extra_forbidden_field"] = "should-not-be-here"
    logger.emit(event)
    assert len(sink) == 1


def test_drop_mode_drops_invalid(
    validating_logger: tuple[AuditLogger, MemorySink],
) -> None:
    logger, sink = validating_logger
    event = make_test_event()
    event["extra_forbidden_field"] = "not-in-schema"
    logger.emit(event)
    assert len(sink) == 0
    assert logger.stats.validation_failures_total >= 1
    assert logger.stats.events_dropped_total >= 1


def test_drop_mode_emits_valid(
    validating_logger: tuple[AuditLogger, MemorySink],
) -> None:
    logger, sink = validating_logger
    event = make_test_event()
    logger.emit(event)
    assert len(sink) == 1


def test_log_and_emit_mode_emits_invalid() -> None:
    sink = MemorySink()
    config = AuditLoggerConfig(
        service_name="test-service",
        service_environment="test",
        validate_events=True,
        validation_failure_mode="log_and_emit",
    )
    logger = AuditLogger(config=config, sink=sink)
    event = make_test_event()
    event["extra_forbidden_field"] = "not-in-schema"
    logger.emit(event)
    assert len(sink) == 1
    assert logger.stats.validation_failures_total >= 1


def test_raise_mode_raises() -> None:
    sink = MemorySink()
    config = AuditLoggerConfig(
        service_name="test-service",
        service_environment="test",
        validate_events=True,
        validation_failure_mode="raise",
    )
    logger = AuditLogger(config=config, sink=sink)
    event = make_test_event()
    event["extra_forbidden_field"] = "not-in-schema"
    with pytest.raises(AuditValidationError) as exc_info:
        logger.emit(event)
    assert exc_info.value.event_id == event["event_id"]
    assert len(exc_info.value.errors) > 0


def test_validation_timing_recorded(
    validating_logger: tuple[AuditLogger, MemorySink],
) -> None:
    logger, sink = validating_logger
    event = make_test_event()
    logger.emit(event)
    assert logger.stats.validation_time_ms_total > 0


def test_audit_method_with_validation() -> None:
    sink = MemorySink()
    config = AuditLoggerConfig(
        service_name="test-service",
        service_environment="test",
        validate_events=True,
        validation_failure_mode="drop",
    )
    logger = AuditLogger(config=config, sink=sink)
    result = logger.audit(
        "READ",
        actor={"subject_id": "user-1", "subject_type": "human"},
        resource={"type": "Patient"},
        outcome={"status": "SUCCESS"},
    )
    assert result is not None
    assert len(sink) == 1


def test_emit_method_with_validation(
    validating_logger: tuple[AuditLogger, MemorySink],
) -> None:
    logger, sink = validating_logger
    event = make_test_event()
    logger.emit(event)
    assert len(sink) == 1
    assert logger.stats.events_emitted_total == 1


def test_emit_method_with_invalid_event_dropped(
    validating_logger: tuple[AuditLogger, MemorySink],
) -> None:
    logger, sink = validating_logger
    event: dict[str, Any] = {"schema_version": "1.1", "event_id": "bad"}
    logger.emit(event)
    assert len(sink) == 0
    assert logger.stats.events_dropped_total >= 1
