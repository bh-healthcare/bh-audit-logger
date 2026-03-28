"""
Schema validation tests for bh-audit-logger v0.3.

Validates that events emitted by AuditLogger conform to the vendored
bh-audit-schema v1.1 JSON schema with FormatChecker enabled (uuid,
date-time formats are enforced).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from bh_audit_logger import AuditLogger, AuditLoggerConfig, MemorySink

jsonschema = pytest.importorskip("jsonschema")

from bh_audit_logger.schema import load_schema  # noqa: E402

_FORMAT_CHECKER = jsonschema.FormatChecker()


@pytest.fixture
def schema() -> dict[str, Any]:
    return load_schema()


@pytest.fixture
def sink() -> MemorySink:
    return MemorySink()


@pytest.fixture
def logger(sink: MemorySink) -> AuditLogger:
    cfg = AuditLoggerConfig(
        service_name="schema-test",
        service_environment="test",
        service_version="0.3.0",
        time_source=lambda: datetime(2026, 3, 28, 12, 0, 0, tzinfo=UTC),
        id_factory=lambda: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    )
    return AuditLogger(config=cfg, sink=sink)


def _validate(event: dict[str, Any], schema: dict[str, Any]) -> None:
    """Validate with FormatChecker so uuid/date-time formats are enforced."""
    jsonschema.validate(instance=event, schema=schema, format_checker=_FORMAT_CHECKER)


class TestEmittedEventsValidateAgainstSchema:
    """Every emitted event must pass full JSON schema validation with format checking."""

    def test_success_event_validates(
        self, logger: AuditLogger, sink: MemorySink, schema: dict[str, Any]
    ) -> None:
        logger.audit(
            "READ",
            actor={"subject_id": "user_1", "subject_type": "human"},
            resource={"type": "Patient", "id": "pat_1"},
        )
        assert len(sink) == 1
        _validate(sink.events[0], schema)

    def test_failure_with_exception_validates(
        self, logger: AuditLogger, sink: MemorySink, schema: dict[str, Any]
    ) -> None:
        logger.audit(
            "UPDATE",
            actor={"subject_id": "user_1", "subject_type": "human"},
            resource={"type": "Note", "id": "note_1"},
            error=ValueError("bad input"),
        )
        assert len(sink) == 1
        event = sink.events[0]
        assert event["outcome"]["status"] == "FAILURE"
        assert event["outcome"]["error_type"] == "ValueError"
        _validate(event, schema)

    def test_failure_with_string_error_validates(
        self, logger: AuditLogger, sink: MemorySink, schema: dict[str, Any]
    ) -> None:
        """v1.1: string error must still produce error_type."""
        logger.audit(
            "DELETE",
            actor={"subject_id": "svc_1", "subject_type": "service"},
            resource={"type": "Patient"},
            error="something failed",
        )
        assert len(sink) == 1
        event = sink.events[0]
        assert event["outcome"]["error_type"] == "ApplicationError"
        _validate(event, schema)

    def test_login_success_validates(
        self, logger: AuditLogger, sink: MemorySink, schema: dict[str, Any]
    ) -> None:
        logger.audit_login_success(
            actor={"subject_id": "user_1", "subject_type": "human"},
        )
        assert len(sink) == 1
        _validate(sink.events[0], schema)

    def test_login_failure_validates(
        self, logger: AuditLogger, sink: MemorySink, schema: dict[str, Any]
    ) -> None:
        logger.audit_login_failure(
            actor={"subject_id": "user_1", "subject_type": "human"},
            error="Invalid credentials",
        )
        assert len(sink) == 1
        event = sink.events[0]
        assert event["outcome"]["status"] == "FAILURE"
        _validate(event, schema)

    def test_event_with_correlation_validates(
        self, logger: AuditLogger, sink: MemorySink, schema: dict[str, Any]
    ) -> None:
        logger.audit(
            "READ",
            actor={"subject_id": "user_1", "subject_type": "human"},
            resource={"type": "Patient"},
            correlation={"request_id": "req_1", "trace_id": "trace_1"},
        )
        assert len(sink) == 1
        _validate(sink.events[0], schema)

    def test_event_with_metadata_validates(self, sink: MemorySink, schema: dict[str, Any]) -> None:
        cfg = AuditLoggerConfig(
            service_name="schema-test",
            service_environment="test",
            metadata_allowlist=frozenset({"region", "count"}),
            id_factory=lambda: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        )
        logger = AuditLogger(config=cfg, sink=sink)
        logger.audit(
            "READ",
            actor={"subject_id": "user_1", "subject_type": "human"},
            resource={"type": "Patient"},
            metadata={"region": "us-east-1", "count": 42},
        )
        assert len(sink) == 1
        _validate(sink.events[0], schema)

    def test_schema_version_is_1_1(self, logger: AuditLogger, sink: MemorySink) -> None:
        logger.audit("READ", resource={"type": "Patient"})
        assert sink.events[0]["schema_version"] == "1.1"


class TestMinimalValidation:
    """Test the minimal validation function against v1.1 rules."""

    def test_accepts_valid_v1_1_event(self) -> None:
        from bh_audit_logger.validation import validate_event_minimal

        event = {
            "schema_version": "1.1",
            "event_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "timestamp": "2026-03-28T12:00:00Z",
            "service": {"name": "test"},
            "actor": {"subject_id": "user_1", "subject_type": "human"},
            "action": {"type": "READ"},
            "resource": {"type": "Patient"},
            "outcome": {"status": "SUCCESS"},
        }
        validate_event_minimal(event)

    def test_rejects_failure_without_error_type(self) -> None:
        from bh_audit_logger.validation import ValidationError, validate_event_minimal

        event = {
            "schema_version": "1.1",
            "event_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "timestamp": "2026-03-28T12:00:00Z",
            "service": {"name": "test"},
            "actor": {"subject_id": "user_1", "subject_type": "human"},
            "action": {"type": "READ"},
            "resource": {"type": "Patient"},
            "outcome": {"status": "FAILURE"},
        }
        with pytest.raises(ValidationError, match="error_type"):
            validate_event_minimal(event)

    def test_rejects_denied_without_error_type(self) -> None:
        from bh_audit_logger.validation import ValidationError, validate_event_minimal

        event = {
            "schema_version": "1.1",
            "event_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "timestamp": "2026-03-28T12:00:00Z",
            "service": {"name": "test"},
            "actor": {"subject_id": "user_1", "subject_type": "human"},
            "action": {"type": "READ"},
            "resource": {"type": "Patient"},
            "outcome": {"status": "DENIED"},
        }
        with pytest.raises(ValidationError, match="error_type"):
            validate_event_minimal(event)

    def test_rejects_invalid_uuid(self) -> None:
        from bh_audit_logger.validation import ValidationError, validate_event_minimal

        event = {
            "schema_version": "1.1",
            "event_id": "not-a-valid-uuid",
            "timestamp": "2026-03-28T12:00:00Z",
            "service": {"name": "test"},
            "actor": {"subject_id": "user_1", "subject_type": "human"},
            "action": {"type": "READ"},
            "resource": {"type": "Patient"},
            "outcome": {"status": "SUCCESS"},
        }
        with pytest.raises(ValidationError, match="UUID"):
            validate_event_minimal(event)
