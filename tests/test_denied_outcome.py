"""
Tests for DENIED outcome support and audit_access_denied().
"""

from __future__ import annotations

import pytest

from bh_audit_logger import (
    AuditLogger,
    AuditLoggerConfig,
    MemorySink,
)


@pytest.fixture
def logger_and_sink() -> tuple[AuditLogger, MemorySink]:
    sink = MemorySink()
    config = AuditLoggerConfig(
        service_name="test-service",
        service_environment="test",
    )
    logger = AuditLogger(config=config, sink=sink)
    return logger, sink


def test_audit_access_denied_basic(
    logger_and_sink: tuple[AuditLogger, MemorySink],
) -> None:
    logger, sink = logger_and_sink
    result = logger.audit_access_denied(
        "READ",
        actor={"subject_id": "user-1", "subject_type": "human"},
        resource={"type": "Patient"},
    )
    assert result is not None
    assert result["outcome"]["status"] == "DENIED"
    assert result["outcome"]["error_type"] == "AccessDenied"
    assert len(sink) == 1


def test_audit_access_denied_custom_error_type(
    logger_and_sink: tuple[AuditLogger, MemorySink],
) -> None:
    logger, sink = logger_and_sink
    result = logger.audit_access_denied(
        "READ",
        error_type="RoleDenied",
        actor={"subject_id": "user-1", "subject_type": "human"},
        resource={"type": "ClinicalNote"},
    )
    assert result is not None
    assert result["outcome"]["error_type"] == "RoleDenied"


def test_audit_access_denied_with_error_message(
    logger_and_sink: tuple[AuditLogger, MemorySink],
) -> None:
    logger, sink = logger_and_sink
    result = logger.audit_access_denied(
        "READ",
        error_type="RoleDenied",
        error_message="Insufficient privileges",
        actor={"subject_id": "user-1", "subject_type": "human"},
        resource={"type": "Patient"},
    )
    assert result is not None
    assert result["outcome"]["error_message"] == "Insufficient privileges"


def test_audit_access_denied_without_error_message(
    logger_and_sink: tuple[AuditLogger, MemorySink],
) -> None:
    logger, sink = logger_and_sink
    result = logger.audit_access_denied(
        "READ",
        actor={"subject_id": "user-1", "subject_type": "human"},
        resource={"type": "Patient"},
    )
    assert result is not None
    assert "error_message" not in result["outcome"]


def test_audit_access_denied_returns_event_or_none() -> None:
    sink = MemorySink()
    config = AuditLoggerConfig(
        service_name="test-service",
        service_environment="test",
    )
    logger = AuditLogger(config=config, sink=sink)
    result = logger.audit_access_denied(
        "READ",
        actor={"subject_id": "user-1", "subject_type": "human"},
        resource={"type": "Patient"},
    )
    assert isinstance(result, dict)
    assert result["outcome"]["status"] == "DENIED"


def test_audit_access_denied_with_phi_touched(
    logger_and_sink: tuple[AuditLogger, MemorySink],
) -> None:
    logger, sink = logger_and_sink
    result = logger.audit_access_denied(
        "READ",
        phi_touched=True,
        data_classification="PHI",
        actor={"subject_id": "user-1", "subject_type": "human"},
        resource={"type": "Patient"},
    )
    assert result is not None
    assert result["action"]["phi_touched"] is True
    assert result["action"]["data_classification"] == "PHI"


@pytest.mark.skipif(
    not pytest.importorskip("jsonschema", reason="needs jsonschema"),
    reason="jsonschema not installed",
)
def test_audit_access_denied_passes_schema_validation(
    logger_and_sink: tuple[AuditLogger, MemorySink],
) -> None:
    from bh_audit_logger import validate_event_schema

    logger, sink = logger_and_sink
    result = logger.audit_access_denied(
        "READ",
        error_type="RoleDenied",
        error_message="No access",
        actor={"subject_id": "user-1", "subject_type": "human"},
        resource={"type": "ClinicalNote"},
    )
    assert result is not None
    errors = validate_event_schema(result, "1.1")
    assert errors == [], f"Schema validation errors: {errors}"


def test_denied_outcome_via_audit_method(
    logger_and_sink: tuple[AuditLogger, MemorySink],
) -> None:
    logger, sink = logger_and_sink
    result = logger.audit(
        "READ",
        actor={"subject_id": "user-1", "subject_type": "human"},
        resource={"type": "Patient"},
        outcome={"status": "DENIED", "error_type": "ConsentDenied"},
    )
    assert result is not None
    assert result["outcome"]["status"] == "DENIED"
    assert result["outcome"]["error_type"] == "ConsentDenied"


def test_denied_without_error_type_caught_by_minimal_validation() -> None:
    """DENIED without error_type should fail minimal validation and return None."""
    sink = MemorySink()
    config = AuditLoggerConfig(
        service_name="test-service",
        service_environment="test",
    )
    logger = AuditLogger(config=config, sink=sink)
    result = logger.audit(
        "READ",
        actor={"subject_id": "user-1", "subject_type": "human"},
        resource={"type": "Patient"},
        outcome={"status": "DENIED"},
    )
    assert result is None
    assert len(sink) == 0


def test_denied_downgrade_to_failure_in_v1_0() -> None:
    sink = MemorySink()
    config = AuditLoggerConfig(
        service_name="test-service",
        service_environment="test",
        target_schema_version="1.0",
    )
    logger = AuditLogger(config=config, sink=sink)
    result = logger.audit_access_denied(
        "READ",
        error_type="RoleDenied",
        actor={"subject_id": "user-1", "subject_type": "human"},
        resource={"type": "Patient"},
    )
    assert result is not None
    assert result["outcome"]["status"] == "FAILURE"
    assert result["outcome"]["error_type"] == "RoleDenied"
    assert result["schema_version"] == "1.0"
