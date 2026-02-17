"""
PHI Safety Tests.

These tests verify that the audit logger never leaks PHI tokens
that appear in inputs. PHI safety is a property enforced by tests.
"""

import json
from typing import Any

from bh_audit_logger import AuditLogger, AuditLoggerConfig, MemorySink
from bh_audit_logger.redaction import (
    contains_phi_tokens,
    redact_tokens,
    sanitize_error_message,
)


def event_to_json(event: dict[str, Any]) -> str:
    """Serialize event to JSON string for token searching."""
    return json.dumps(event, default=str)


def assert_no_phi_tokens(event: dict[str, Any], tokens: list[str]) -> None:
    """Assert that no PHI tokens appear in the serialized event."""
    event_json = event_to_json(event)
    found = contains_phi_tokens(event_json, tokens)
    assert not found, f"PHI tokens found in event: {found}\nEvent: {event_json}"


class TestErrorMessageSanitized:
    """Test that error messages are sanitized before logging."""

    def test_ssn_in_error_is_redacted(self, memory_sink: MemorySink, phi_tokens: list[str]) -> None:
        """SSN pattern in error message should be redacted."""
        cfg = AuditLoggerConfig(
            service_name="phi-test",
            service_environment="test",
            id_factory=lambda: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        )
        logger = AuditLogger(config=cfg, sink=memory_sink)
        event = logger.audit(
            "READ",
            resource={"type": "Patient"},
            error="Failed for SSN 123-45-6789",
        )
        assert "123-45-6789" not in event["outcome"]["error_message"]
        assert "[REDACTED-SSN]" in event["outcome"]["error_message"]
        assert_no_phi_tokens(event, phi_tokens)

    def test_email_in_error_is_redacted(
        self, memory_sink: MemorySink, phi_tokens: list[str]
    ) -> None:
        """Email in error message should be redacted."""
        cfg = AuditLoggerConfig(
            service_name="phi-test",
            id_factory=lambda: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        )
        logger = AuditLogger(config=cfg, sink=memory_sink)
        event = logger.audit(
            "READ",
            resource={"type": "Patient"},
            error="Failed to send to patient@hospital.com",
        )
        assert "patient@hospital.com" not in event["outcome"]["error_message"]
        assert "[REDACTED-EMAIL]" in event["outcome"]["error_message"]

    def test_phone_in_error_is_redacted(
        self,
        memory_sink: MemorySink,
    ) -> None:
        """Phone number in error message should be redacted."""
        cfg = AuditLoggerConfig(
            service_name="phi-test",
            id_factory=lambda: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        )
        logger = AuditLogger(config=cfg, sink=memory_sink)
        event = logger.audit(
            "READ",
            resource={"type": "Patient"},
            error="Contact at 555-123-4567 unreachable",
        )
        assert "555-123-4567" not in event["outcome"]["error_message"]
        assert "[REDACTED-PHONE]" in event["outcome"]["error_message"]

    def test_long_error_truncated(self, memory_sink: MemorySink) -> None:
        """Very long error messages should be truncated."""
        cfg = AuditLoggerConfig(
            service_name="phi-test",
            error_message_max_len=100,
            id_factory=lambda: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        )
        logger = AuditLogger(config=cfg, sink=memory_sink)
        event = logger.audit(
            "READ",
            resource={"type": "Patient"},
            error="x" * 500,
        )
        assert len(event["outcome"]["error_message"]) <= 100
        assert event["outcome"]["error_message"].endswith("...")

    def test_exception_with_phi_sanitized(
        self, memory_sink: MemorySink, phi_tokens: list[str]
    ) -> None:
        """Exception containing PHI tokens should be sanitized."""
        cfg = AuditLoggerConfig(
            service_name="phi-test",
            id_factory=lambda: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        )
        logger = AuditLogger(config=cfg, sink=memory_sink)

        exc = ValueError(f"Patient {phi_tokens[2]} has SSN 123-45-6789")
        event = logger.audit(
            "READ",
            resource={"type": "Patient"},
            error=exc,
        )
        assert "123-45-6789" not in event["outcome"]["error_message"]
        assert event["outcome"]["error_type"] == "ValueError"


class TestMetadataAllowlistPHI:
    """Test that metadata is strictly filtered to prevent PHI leakage."""

    def test_phi_in_metadata_dropped_by_allowlist(
        self, memory_sink: MemorySink, phi_tokens: list[str]
    ) -> None:
        """PHI in metadata should be dropped if key not in allowlist."""
        cfg = AuditLoggerConfig(
            service_name="phi-test",
            metadata_allowlist={"safe_key"},
            id_factory=lambda: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        )
        logger = AuditLogger(config=cfg, sink=memory_sink)
        event = logger.audit(
            "READ",
            resource={"type": "Patient"},
            metadata={
                "safe_key": "safe_value",
                "patient_name": phi_tokens[2],
                "diagnosis": phi_tokens[3],
                "ssn": phi_tokens[0],
            },
        )
        assert event["metadata"] == {"safe_key": "safe_value"}
        assert_no_phi_tokens(event, phi_tokens)

    def test_empty_allowlist_blocks_all_metadata(
        self, memory_sink: MemorySink, phi_tokens: list[str]
    ) -> None:
        """Empty allowlist should result in no metadata at all."""
        cfg = AuditLoggerConfig(
            service_name="phi-test",
            metadata_allowlist=set(),
            id_factory=lambda: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        )
        logger = AuditLogger(config=cfg, sink=memory_sink)
        event = logger.audit(
            "READ",
            resource={"type": "Patient"},
            metadata={
                "patient_name": phi_tokens[2],
                "notes": phi_tokens[4],
            },
        )
        assert "metadata" not in event
        assert_no_phi_tokens(event, phi_tokens)

    def test_no_metadata_means_no_metadata(self, memory_sink: MemorySink) -> None:
        """When no metadata provided, none appears."""
        cfg = AuditLoggerConfig(
            service_name="phi-test",
            id_factory=lambda: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        )
        logger = AuditLogger(config=cfg, sink=memory_sink)
        event = logger.audit("READ", resource={"type": "Patient"})
        assert "metadata" not in event


class TestFullEventPHISafety:
    """End-to-end test: complete events must not contain synthetic PHI."""

    def test_metadata_phi_blocked_in_full_event(
        self, memory_sink: MemorySink, phi_tokens: list[str]
    ) -> None:
        """PHI in metadata must be blocked by allowlist; only safe keys survive."""
        cfg = AuditLoggerConfig(
            service_name="phi-test",
            metadata_allowlist={"safe"},
            id_factory=lambda: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        )
        logger = AuditLogger(config=cfg, sink=memory_sink)
        event = logger.audit(
            "READ",
            actor={"subject_id": "user_1", "subject_type": "human"},
            resource={"type": "Patient", "id": "pat_1"},
            outcome={"status": "SUCCESS"},
            metadata={
                "safe": "ok",
                "patient_name": phi_tokens[2],
                "ssn": phi_tokens[0],
            },
            correlation={"request_id": "req_abc"},
        )
        assert event["metadata"] == {"safe": "ok"}
        assert_no_phi_tokens(event, phi_tokens)

    def test_real_ssn_in_error_redacted_in_full_event(self, memory_sink: MemorySink) -> None:
        """Real SSN/email/phone patterns in error messages are redacted end-to-end."""
        cfg = AuditLoggerConfig(
            service_name="phi-test",
            metadata_allowlist=set(),
            id_factory=lambda: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        )
        logger = AuditLogger(config=cfg, sink=memory_sink)
        event = logger.audit(
            "READ",
            actor={"subject_id": "user_1", "subject_type": "human"},
            resource={"type": "Patient", "id": "pat_1"},
            error=ValueError("Patient lookup failed for SSN 123-45-6789 email jane@hospital.com"),
        )
        event_json = event_to_json(event)
        assert "123-45-6789" not in event_json
        assert "jane@hospital.com" not in event_json
        assert "[REDACTED-SSN]" in event_json
        assert "[REDACTED-EMAIL]" in event_json

    def test_metadata_fully_blocked_in_serialized_json(
        self, memory_sink: MemorySink, phi_tokens: list[str]
    ) -> None:
        """Serialized JSON of event must not contain blocked metadata tokens."""
        cfg = AuditLoggerConfig(
            service_name="phi-test",
            metadata_allowlist=set(),
            id_factory=lambda: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        )
        logger = AuditLogger(config=cfg, sink=memory_sink)
        event = logger.audit(
            "UPDATE",
            resource={"type": "Note"},
            outcome={"status": "SUCCESS"},
            metadata={
                "patient_name": phi_tokens[2],
                "notes": phi_tokens[4],
            },
        )
        assert "metadata" not in event
        event_json = event_to_json(event)
        found = contains_phi_tokens(event_json, phi_tokens)
        assert not found, f"PHI tokens found in JSON: {found}"


class TestRedactionUtilities:
    """Test the redaction utility functions directly."""

    def test_sanitize_removes_ssn_pattern(self) -> None:
        msg = "Error for SSN 123-45-6789"
        result = sanitize_error_message(msg)
        assert "123-45-6789" not in result
        assert "[REDACTED-SSN]" in result

    def test_sanitize_removes_email(self) -> None:
        msg = "Contact jane.doe@example.com for help"
        result = sanitize_error_message(msg)
        assert "jane.doe@example.com" not in result
        assert "[REDACTED-EMAIL]" in result

    def test_sanitize_removes_phone(self) -> None:
        msg = "Call 555-123-4567 for help"
        result = sanitize_error_message(msg)
        assert "555-123-4567" not in result
        assert "[REDACTED-PHONE]" in result

    def test_sanitize_truncates_long_messages(self) -> None:
        msg = "x" * 500
        result = sanitize_error_message(msg, max_len=100)
        assert len(result) == 100
        assert result.endswith("...")

    def test_sanitize_normalizes_whitespace(self) -> None:
        msg = "Line1\nLine2\n\nLine3   extra   spaces"
        result = sanitize_error_message(msg)
        assert "\n" not in result
        assert "   " not in result

    def test_sanitize_empty_message(self) -> None:
        assert sanitize_error_message("") == ""

    def test_contains_phi_tokens_finds_matches(self, phi_tokens: list[str]) -> None:
        text = f"Patient {phi_tokens[2]} has diagnosis {phi_tokens[3]}"
        found = contains_phi_tokens(text, phi_tokens)
        assert phi_tokens[2] in found
        assert phi_tokens[3] in found
        assert len(found) == 2

    def test_contains_phi_tokens_case_insensitive(self, phi_tokens: list[str]) -> None:
        text = "patient_jane_doe is here"
        found = contains_phi_tokens(text, phi_tokens)
        assert phi_tokens[2] in found

    def test_contains_phi_tokens_empty_text(self, phi_tokens: list[str]) -> None:
        found = contains_phi_tokens("", phi_tokens)
        assert found == []

    def test_redact_tokens_replaces_values(self, phi_tokens: list[str]) -> None:
        text = f"Patient {phi_tokens[2]} SSN {phi_tokens[0]}"
        result = redact_tokens(text, phi_tokens)
        assert phi_tokens[0] not in result
        assert phi_tokens[2] not in result
        assert "[REDACTED]" in result

    def test_redact_tokens_custom_replacement(self) -> None:
        result = redact_tokens("secret_value here", ["secret_value"], replacement="***")
        assert "secret_value" not in result
        assert "***" in result
