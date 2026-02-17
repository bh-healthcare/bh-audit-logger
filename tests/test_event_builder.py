"""
Tests for AuditLogger event building.

Verifies that the audit() method produces correct event structure
with all required fields, proper defaults, and sanitization.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from bh_audit_logger import AuditLogger, AuditLoggerConfig, MemorySink


@pytest.fixture
def fixed_config() -> AuditLoggerConfig:
    """Config with fixed time and ID for deterministic tests."""
    return AuditLoggerConfig(
        service_name="builder-test",
        service_environment="test",
        service_version="1.2.3",
        time_source=lambda: datetime(2026, 2, 17, 12, 0, 0, tzinfo=UTC),
        id_factory=lambda: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    )


class TestRequiredFields:
    """Verify all required top-level fields are present and correct."""

    def test_produces_all_required_keys(
        self, fixed_config: AuditLoggerConfig, memory_sink: MemorySink
    ) -> None:
        """audit() must produce all required bh-audit-schema v1.0 keys."""
        logger = AuditLogger(config=fixed_config, sink=memory_sink)
        event = logger.audit(
            "READ",
            actor={"subject_id": "user_1", "subject_type": "human"},
            resource={"type": "Patient", "id": "pat_1"},
        )

        required_keys = {
            "schema_version",
            "event_id",
            "timestamp",
            "service",
            "actor",
            "action",
            "resource",
            "outcome",
        }
        assert required_keys.issubset(set(event.keys()))

    def test_schema_version_is_1_0(
        self, fixed_config: AuditLoggerConfig, memory_sink: MemorySink
    ) -> None:
        logger = AuditLogger(config=fixed_config, sink=memory_sink)
        event = logger.audit("READ", resource={"type": "Patient"})
        assert event["schema_version"] == "1.0"

    def test_event_id_is_deterministic(
        self, fixed_config: AuditLoggerConfig, memory_sink: MemorySink
    ) -> None:
        logger = AuditLogger(config=fixed_config, sink=memory_sink)
        event = logger.audit("READ", resource={"type": "Patient"})
        assert event["event_id"] == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

    def test_timestamp_is_utc_with_z(
        self, fixed_config: AuditLoggerConfig, memory_sink: MemorySink
    ) -> None:
        logger = AuditLogger(config=fixed_config, sink=memory_sink)
        event = logger.audit("READ", resource={"type": "Patient"})
        assert event["timestamp"] == "2026-02-17T12:00:00Z"

    def test_service_block(self, fixed_config: AuditLoggerConfig, memory_sink: MemorySink) -> None:
        logger = AuditLogger(config=fixed_config, sink=memory_sink)
        event = logger.audit("READ", resource={"type": "Patient"})
        assert event["service"] == {
            "name": "builder-test",
            "environment": "test",
            "version": "1.2.3",
        }

    def test_service_block_without_version(self, memory_sink: MemorySink) -> None:
        """Service version is omitted when not configured."""
        cfg = AuditLoggerConfig(
            service_name="no-version",
            service_environment="dev",
            id_factory=lambda: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        )
        logger = AuditLogger(config=cfg, sink=memory_sink)
        event = logger.audit("READ", resource={"type": "Patient"})
        assert "version" not in event["service"]

    def test_event_is_emitted_to_sink(
        self, fixed_config: AuditLoggerConfig, memory_sink: MemorySink
    ) -> None:
        logger = AuditLogger(config=fixed_config, sink=memory_sink)
        logger.audit("READ", resource={"type": "Patient"})
        assert len(memory_sink) == 1

    def test_event_is_returned(
        self, fixed_config: AuditLoggerConfig, memory_sink: MemorySink
    ) -> None:
        logger = AuditLogger(config=fixed_config, sink=memory_sink)
        event = logger.audit("READ", resource={"type": "Patient"})
        assert event is not None
        assert event == memory_sink.events[0]


class TestActorDefaults:
    """Verify actor defaults and override behaviour."""

    def test_default_actor_applied(self, memory_sink: MemorySink) -> None:
        cfg = AuditLoggerConfig(
            service_name="test",
            default_actor_id="svc_default",
            default_actor_type="service",
            id_factory=lambda: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        )
        logger = AuditLogger(config=cfg, sink=memory_sink)
        event = logger.audit("READ", resource={"type": "Patient"})
        assert event["actor"]["subject_id"] == "svc_default"
        assert event["actor"]["subject_type"] == "service"

    def test_explicit_actor_overrides_defaults(self, memory_sink: MemorySink) -> None:
        cfg = AuditLoggerConfig(
            service_name="test",
            default_actor_id="svc_default",
            id_factory=lambda: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        )
        logger = AuditLogger(config=cfg, sink=memory_sink)
        event = logger.audit(
            "READ",
            actor={"subject_id": "user_42", "subject_type": "human", "org_id": "org_7"},
            resource={"type": "Patient"},
        )
        assert event["actor"]["subject_id"] == "user_42"
        assert event["actor"]["subject_type"] == "human"
        assert event["actor"]["org_id"] == "org_7"

    def test_partial_actor_gets_defaults(self, memory_sink: MemorySink) -> None:
        """Supplying only subject_id should still get default subject_type."""
        cfg = AuditLoggerConfig(
            service_name="test",
            default_actor_type="service",
            id_factory=lambda: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        )
        logger = AuditLogger(config=cfg, sink=memory_sink)
        event = logger.audit(
            "READ",
            actor={"subject_id": "user_99"},
            resource={"type": "Patient"},
        )
        assert event["actor"]["subject_id"] == "user_99"
        assert event["actor"]["subject_type"] == "service"


class TestActionBlock:
    """Verify action block construction."""

    def test_action_type_set(
        self, fixed_config: AuditLoggerConfig, memory_sink: MemorySink
    ) -> None:
        logger = AuditLogger(config=fixed_config, sink=memory_sink)
        event = logger.audit("CREATE", resource={"type": "Note"})
        assert event["action"]["type"] == "CREATE"

    def test_data_classification_defaults_to_unknown(
        self, fixed_config: AuditLoggerConfig, memory_sink: MemorySink
    ) -> None:
        logger = AuditLogger(config=fixed_config, sink=memory_sink)
        event = logger.audit("READ", resource={"type": "Patient"})
        assert event["action"]["data_classification"] == "UNKNOWN"

    def test_phi_touched_set(
        self, fixed_config: AuditLoggerConfig, memory_sink: MemorySink
    ) -> None:
        logger = AuditLogger(config=fixed_config, sink=memory_sink)
        event = logger.audit(
            "READ",
            resource={"type": "Patient"},
            phi_touched=True,
            data_classification="PHI",
        )
        assert event["action"]["phi_touched"] is True
        assert event["action"]["data_classification"] == "PHI"

    def test_phi_touched_omitted_when_none(
        self, fixed_config: AuditLoggerConfig, memory_sink: MemorySink
    ) -> None:
        logger = AuditLogger(config=fixed_config, sink=memory_sink)
        event = logger.audit("READ", resource={"type": "Patient"})
        assert "phi_touched" not in event["action"]


class TestOutcomeBlock:
    """Verify outcome construction and error sanitization."""

    def test_default_outcome_is_success(
        self, fixed_config: AuditLoggerConfig, memory_sink: MemorySink
    ) -> None:
        logger = AuditLogger(config=fixed_config, sink=memory_sink)
        event = logger.audit("READ", resource={"type": "Patient"})
        assert event["outcome"]["status"] == "SUCCESS"

    def test_explicit_outcome(
        self, fixed_config: AuditLoggerConfig, memory_sink: MemorySink
    ) -> None:
        logger = AuditLogger(config=fixed_config, sink=memory_sink)
        event = logger.audit(
            "DELETE",
            resource={"type": "Patient"},
            outcome={"status": "FAILURE", "error_message": "Not authorized"},
        )
        assert event["outcome"]["status"] == "FAILURE"

    def test_error_string_creates_failure(
        self, fixed_config: AuditLoggerConfig, memory_sink: MemorySink
    ) -> None:
        logger = AuditLogger(config=fixed_config, sink=memory_sink)
        event = logger.audit(
            "UPDATE",
            resource={"type": "Patient"},
            error="Something went wrong",
        )
        assert event["outcome"]["status"] == "FAILURE"
        assert "Something went wrong" in event["outcome"]["error_message"]

    def test_error_exception_creates_failure_with_type(
        self, fixed_config: AuditLoggerConfig, memory_sink: MemorySink
    ) -> None:
        logger = AuditLogger(config=fixed_config, sink=memory_sink)
        event = logger.audit(
            "UPDATE",
            resource={"type": "Patient"},
            error=ValueError("bad value"),
        )
        assert event["outcome"]["status"] == "FAILURE"
        assert event["outcome"]["error_type"] == "ValueError"

    def test_error_message_sanitized_ssn(
        self, fixed_config: AuditLoggerConfig, memory_sink: MemorySink
    ) -> None:
        """SSN pattern in error should be redacted."""
        logger = AuditLogger(config=fixed_config, sink=memory_sink)
        event = logger.audit(
            "READ",
            resource={"type": "Patient"},
            error="Lookup failed for SSN 123-45-6789",
        )
        assert "123-45-6789" not in event["outcome"]["error_message"]
        assert "[REDACTED-SSN]" in event["outcome"]["error_message"]

    def test_error_message_truncated(self, memory_sink: MemorySink) -> None:
        """Long error messages should be truncated."""
        cfg = AuditLoggerConfig(
            service_name="test",
            error_message_max_len=50,
            id_factory=lambda: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        )
        logger = AuditLogger(config=cfg, sink=memory_sink)
        event = logger.audit(
            "READ",
            resource={"type": "Patient"},
            error="x" * 200,
        )
        assert len(event["outcome"]["error_message"]) <= 50
        assert event["outcome"]["error_message"].endswith("...")

    def test_sanitization_disabled(self, memory_sink: MemorySink) -> None:
        """When sanitize_errors=False, raw error is preserved."""
        cfg = AuditLoggerConfig(
            service_name="test",
            sanitize_errors=False,
            id_factory=lambda: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        )
        logger = AuditLogger(config=cfg, sink=memory_sink)
        event = logger.audit(
            "READ",
            resource={"type": "Patient"},
            error="SSN 123-45-6789",
        )
        assert "123-45-6789" in event["outcome"]["error_message"]


class TestCorrelation:
    """Verify correlation block behaviour."""

    def test_correlation_included(
        self, fixed_config: AuditLoggerConfig, memory_sink: MemorySink
    ) -> None:
        logger = AuditLogger(config=fixed_config, sink=memory_sink)
        event = logger.audit(
            "READ",
            resource={"type": "Patient"},
            correlation={"request_id": "req_abc", "trace_id": "trace_xyz"},
        )
        assert event["correlation"]["request_id"] == "req_abc"
        assert event["correlation"]["trace_id"] == "trace_xyz"

    def test_correlation_omitted_when_none(
        self, fixed_config: AuditLoggerConfig, memory_sink: MemorySink
    ) -> None:
        logger = AuditLogger(config=fixed_config, sink=memory_sink)
        event = logger.audit("READ", resource={"type": "Patient"})
        assert "correlation" not in event


class TestMetadataAllowlist:
    """Verify metadata filtering."""

    def test_metadata_dropped_without_allowlist(self, memory_sink: MemorySink) -> None:
        """Empty allowlist means no metadata at all."""
        cfg = AuditLoggerConfig(
            service_name="test",
            metadata_allowlist=set(),
            id_factory=lambda: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        )
        logger = AuditLogger(config=cfg, sink=memory_sink)
        event = logger.audit(
            "READ",
            resource={"type": "Patient"},
            metadata={"sensitive_key": "sensitive_value"},
        )
        assert "metadata" not in event

    def test_metadata_filtered_by_allowlist(self, memory_sink: MemorySink) -> None:
        cfg = AuditLoggerConfig(
            service_name="test",
            metadata_allowlist={"safe_key"},
            id_factory=lambda: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        )
        logger = AuditLogger(config=cfg, sink=memory_sink)
        event = logger.audit(
            "READ",
            resource={"type": "Patient"},
            metadata={"safe_key": "safe_value", "secret": "bad"},
        )
        assert event["metadata"] == {"safe_key": "safe_value"}

    def test_non_scalar_metadata_dropped(self, memory_sink: MemorySink) -> None:
        """List/dict values in metadata should be silently dropped."""
        cfg = AuditLoggerConfig(
            service_name="test",
            metadata_allowlist={"good", "bad_list", "bad_dict"},
            id_factory=lambda: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        )
        logger = AuditLogger(config=cfg, sink=memory_sink)
        event = logger.audit(
            "READ",
            resource={"type": "Patient"},
            metadata={
                "good": "scalar",
                "bad_list": [1, 2, 3],
                "bad_dict": {"nested": True},
            },
        )
        assert event["metadata"] == {"good": "scalar"}

    def test_null_metadata_value_allowed(self, memory_sink: MemorySink) -> None:
        """None is a valid scalar JSON value."""
        cfg = AuditLoggerConfig(
            service_name="test",
            metadata_allowlist={"nullable"},
            id_factory=lambda: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        )
        logger = AuditLogger(config=cfg, sink=memory_sink)
        event = logger.audit(
            "READ",
            resource={"type": "Patient"},
            metadata={"nullable": None},
        )
        assert event["metadata"] == {"nullable": None}


class TestConvenienceHelpers:
    """Verify convenience methods."""

    def test_audit_login_success(
        self, fixed_config: AuditLoggerConfig, memory_sink: MemorySink
    ) -> None:
        logger = AuditLogger(config=fixed_config, sink=memory_sink)
        event = logger.audit_login_success(
            actor={"subject_id": "user_1", "subject_type": "human"},
        )
        assert event["action"]["type"] == "LOGIN"
        assert event["outcome"]["status"] == "SUCCESS"
        assert event["resource"]["type"] == "Session"

    def test_audit_login_failure(
        self, fixed_config: AuditLoggerConfig, memory_sink: MemorySink
    ) -> None:
        logger = AuditLogger(config=fixed_config, sink=memory_sink)
        event = logger.audit_login_failure(
            actor={"subject_id": "user_1", "subject_type": "human"},
            error="Invalid credentials",
        )
        assert event["action"]["type"] == "LOGIN"
        assert event["outcome"]["status"] == "FAILURE"

    def test_audit_access_read(
        self, fixed_config: AuditLoggerConfig, memory_sink: MemorySink
    ) -> None:
        logger = AuditLogger(config=fixed_config, sink=memory_sink)
        event = logger.audit_access(
            "READ",
            actor={"subject_id": "user_1", "subject_type": "human"},
            resource={"type": "Patient", "id": "pat_1"},
            phi_touched=True,
            data_classification="PHI",
        )
        assert event["action"]["type"] == "READ"
        assert event["action"]["phi_touched"] is True


class TestEventSerialization:
    """Verify events are JSON-serializable."""

    def test_event_is_json_serializable(
        self, fixed_config: AuditLoggerConfig, memory_sink: MemorySink
    ) -> None:
        logger = AuditLogger(config=fixed_config, sink=memory_sink)
        event = logger.audit(
            "READ",
            actor={"subject_id": "user_1", "subject_type": "human"},
            resource={"type": "Patient", "id": "pat_1"},
            correlation={"request_id": "req_1"},
            metadata=None,
        )
        line = json.dumps(event, separators=(",", ":"), ensure_ascii=False)
        assert isinstance(line, str)
        parsed = json.loads(line)
        assert parsed["event_id"] == event["event_id"]
