"""
Test that the public API surface is correctly exported.

This test ensures that users can import the documented public API
and prevents accidental breaking changes to exports.
"""


def test_public_api_imports() -> None:
    """All documented public symbols should be importable from the top-level package."""
    from bh_audit_logger import (
        AuditLogger,
        AuditLoggerConfig,
        AuditSink,
        AuditValidationError,
        EmitQueue,
        JsonlFileSink,
        LoggingSink,
        MemorySink,
        ValidationError,
        contains_phi_tokens,
        redact_tokens,
        sanitize_error_message,
        validate_event_minimal,
        validate_event_schema,
    )

    assert AuditLogger is not None
    assert AuditLoggerConfig is not None
    assert AuditSink is not None
    assert AuditValidationError is not None
    assert JsonlFileSink is not None
    assert LoggingSink is not None
    assert MemorySink is not None
    assert EmitQueue is not None
    assert ValidationError is not None
    assert callable(sanitize_error_message)
    assert callable(contains_phi_tokens)
    assert callable(redact_tokens)
    assert callable(validate_event_minimal)
    assert callable(validate_event_schema)


def test_typed_event_blocks_importable() -> None:
    """TypedDict event blocks should be importable from the top-level package."""
    from bh_audit_logger import (
        ActionBlock,
        ActionType,
        ActorBlock,
        ActorType,
        AuditEvent,
        CorrelationBlock,
        DataClassification,
        OutcomeBlock,
        OutcomeStatus,
        ResourceBlock,
        ServiceBlock,
    )

    assert ActionBlock is not None
    assert ActionType is not None
    assert ActorBlock is not None
    assert ActorType is not None
    assert AuditEvent is not None
    assert CorrelationBlock is not None
    assert DataClassification is not None
    assert OutcomeBlock is not None
    assert OutcomeStatus is not None
    assert ResourceBlock is not None
    assert ServiceBlock is not None


def test_version_exposed() -> None:
    """Package version should be accessible."""
    from bh_audit_logger import __version__

    assert isinstance(__version__, str)
    assert __version__ == "0.4.0"


def test_all_exports_defined() -> None:
    """__all__ should include all documented public symbols."""
    import bh_audit_logger

    expected_exports = {
        "__version__",
        "AuditLogger",
        "AuditLoggerConfig",
        "AuditStats",
        "EmitQueue",
        # Chain hashing / integrity
        "ChainState",
        "DynamoDBChainState",
        "canonical_serialize",
        "compute_chain_hash",
        # Types
        "ActionBlock",
        "ActionType",
        "ActorBlock",
        "ActorType",
        "AuditEvent",
        "CorrelationBlock",
        "DataClassification",
        "EmitFailureMode",
        "HashAlgorithm",
        "IntegrityBlock",
        "OutcomeBlock",
        "OutcomeStatus",
        "ResourceBlock",
        "ServiceBlock",
        # Sinks
        "AuditSink",
        "DynamoDBSink",
        "JsonlFileSink",
        "LedgerSink",
        "LoggingSink",
        "MemorySink",
        # Redaction
        "contains_phi_tokens",
        "redact_tokens",
        "sanitize_error_message",
        # Validation
        "AuditValidationError",
        "ValidationError",
        "validate_event",
        "validate_event_minimal",
        "validate_event_schema",
    }

    assert set(bh_audit_logger.__all__) == expected_exports


def test_sinks_conform_to_protocol() -> None:
    """All built-in sinks should conform to AuditSink protocol."""
    from bh_audit_logger import AuditSink, JsonlFileSink, LoggingSink, MemorySink

    assert isinstance(LoggingSink(), AuditSink)
    assert isinstance(MemorySink(), AuditSink)
    assert hasattr(JsonlFileSink, "emit")


def test_dynamodb_sink_importable() -> None:
    """DynamoDBSink should be importable when boto3 is available."""
    import pytest

    pytest.importorskip("boto3")
    from bh_audit_logger import DynamoDBSink

    assert hasattr(DynamoDBSink, "emit")
    assert hasattr(DynamoDBSink, "query_by_patient")
    assert hasattr(DynamoDBSink, "query_by_actor")
    assert hasattr(DynamoDBSink, "query_denials")


def test_audit_logger_has_expected_methods() -> None:
    """AuditLogger should expose expected methods."""
    from bh_audit_logger import AuditLogger

    assert hasattr(AuditLogger, "emit")
    assert hasattr(AuditLogger, "audit")
    assert hasattr(AuditLogger, "audit_login_success")
    assert hasattr(AuditLogger, "audit_login_failure")
    assert hasattr(AuditLogger, "audit_access")
    assert hasattr(AuditLogger, "audit_access_denied")


def test_chain_hashing_exports() -> None:
    """Chain hashing public API should be importable."""
    from bh_audit_logger import (
        ChainState,
        HashAlgorithm,
        IntegrityBlock,
        LedgerSink,
        canonical_serialize,
        compute_chain_hash,
    )

    assert ChainState is not None
    assert LedgerSink is not None
    assert callable(canonical_serialize)
    assert callable(compute_chain_hash)
    assert HashAlgorithm is not None
    assert IntegrityBlock is not None


def test_dynamodb_chain_state_importable() -> None:
    """DynamoDBChainState should be importable when boto3 is available."""
    import pytest

    pytest.importorskip("boto3")
    from bh_audit_logger import DynamoDBChainState

    assert hasattr(DynamoDBChainState, "advance")
    assert hasattr(DynamoDBChainState, "table_name")
    assert hasattr(DynamoDBChainState, "service_name")
    assert hasattr(DynamoDBChainState, "last_hash")
