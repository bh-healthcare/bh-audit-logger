"""
Tests for schema version negotiation (target_schema_version config).

Tests that call validate_event_schema() require the [jsonschema] extra.
"""

from __future__ import annotations

import pytest

from bh_audit_logger import (
    AuditLogger,
    AuditLoggerConfig,
    MemorySink,
)
from bh_audit_logger.schema import load_schema

pytest.importorskip("jsonschema", reason="jsonschema required for schema negotiation tests")

from bh_audit_logger import validate_event_schema  # noqa: E402


def test_target_1_1_default_schema_version() -> None:
    sink = MemorySink()
    config = AuditLoggerConfig(service_name="test-service", service_environment="test")
    logger = AuditLogger(config=config, sink=sink)
    result = logger.audit(
        "READ",
        actor={"subject_id": "user-1", "subject_type": "human"},
        resource={"type": "Patient"},
    )
    assert result is not None
    assert result["schema_version"] == "1.1"


def test_target_1_0_emits_1_0() -> None:
    sink = MemorySink()
    config = AuditLoggerConfig(
        service_name="test-service",
        service_environment="test",
        target_schema_version="1.0",
    )
    logger = AuditLogger(config=config, sink=sink)
    result = logger.audit(
        "READ",
        actor={"subject_id": "user-1", "subject_type": "human"},
        resource={"type": "Patient"},
    )
    assert result is not None
    assert result["schema_version"] == "1.0"


def test_target_1_0_denied_becomes_failure() -> None:
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


def test_target_1_0_events_pass_1_0_schema() -> None:
    sink = MemorySink()
    config = AuditLoggerConfig(
        service_name="test-service",
        service_environment="test",
        target_schema_version="1.0",
    )
    logger = AuditLogger(config=config, sink=sink)
    result = logger.audit(
        "READ",
        actor={"subject_id": "user-1", "subject_type": "human"},
        resource={"type": "Patient"},
    )
    assert result is not None
    errors = validate_event_schema(result, "1.0")
    assert errors == [], f"Schema validation errors: {errors}"


def test_target_1_1_events_pass_1_1_schema() -> None:
    sink = MemorySink()
    config = AuditLoggerConfig(
        service_name="test-service",
        service_environment="test",
        target_schema_version="1.1",
    )
    logger = AuditLogger(config=config, sink=sink)
    result = logger.audit(
        "READ",
        actor={"subject_id": "user-1", "subject_type": "human"},
        resource={"type": "Patient"},
    )
    assert result is not None
    errors = validate_event_schema(result, "1.1")
    assert errors == [], f"Schema validation errors: {errors}"


def test_load_schema_version_aware() -> None:
    schema_10 = load_schema("1.0")
    schema_11 = load_schema("1.1")
    assert schema_10["properties"]["schema_version"]["const"] == "1.0"
    assert schema_11["properties"]["schema_version"]["const"] == "1.1"
