"""
bh-audit-logger: PHI-safe audit logging utilities for Python.

Cloud-agnostic utilities for emitting structured audit events
conforming to bh-audit-schema v1.1 for behavioral healthcare systems.
"""

__version__ = "1.1.0"

from bh_audit_logger._chain import canonical_serialize, compute_chain_hash
from bh_audit_logger._chain_state import ChainState
from bh_audit_logger._queue import EmitQueue
from bh_audit_logger._stats import AuditStats
from bh_audit_logger._types import (
    ActionBlock,
    ActionType,
    ActorBlock,
    ActorType,
    AuditEvent,
    CorrelationBlock,
    DataClassification,
    EmitFailureMode,
    HashAlgorithm,
    IntegrityBlock,
    OutcomeBlock,
    OutcomeStatus,
    ResourceBlock,
    ServiceBlock,
)
from bh_audit_logger._validation import AuditValidationError, validate_event_schema
from bh_audit_logger._verifier import VerifyFailure, VerifyResult, verify_chain
from bh_audit_logger.config import AuditLoggerConfig
from bh_audit_logger.logger import AuditLogger
from bh_audit_logger.redaction import (
    contains_phi_tokens,
    redact_tokens,
    sanitize_error_message,
)
from bh_audit_logger.sinks import (
    AuditSink,
    JsonlFileSink,
    LedgerSink,
    LoggingSink,
    MemorySink,
)

try:
    from bh_audit_logger._chain_state import DynamoDBChainState
except ImportError:
    pass

try:
    from bh_audit_logger.sinks.dynamodb import DynamoDBSink
except ImportError:
    pass
from bh_audit_logger.validation import ValidationError, validate_event, validate_event_minimal


def __getattr__(name: str) -> object:
    if name == "DynamoDBSink":
        raise ImportError(
            "DynamoDBSink requires boto3. Install with: pip install bh-audit-logger[dynamodb]"
        )
    if name == "DynamoDBChainState":
        raise ImportError(
            "DynamoDBChainState requires boto3. Install with: pip install bh-audit-logger[dynamodb]"
        )
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "__version__",
    # Core
    "AuditLogger",
    "AuditLoggerConfig",
    "AuditStats",
    "EmitQueue",
    # Chain hashing / integrity
    "ChainState",
    "DynamoDBChainState",
    "canonical_serialize",
    "compute_chain_hash",
    # Type definitions
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
    # Redaction utilities
    "contains_phi_tokens",
    "redact_tokens",
    "sanitize_error_message",
    # Verifier
    "VerifyFailure",
    "VerifyResult",
    "verify_chain",
    # Validation
    "AuditValidationError",
    "ValidationError",
    "validate_event",
    "validate_event_minimal",
    "validate_event_schema",
]
