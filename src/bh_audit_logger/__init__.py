"""
bh-audit-logger: PHI-safe audit logging utilities for Python.

Cloud-agnostic utilities for emitting structured audit events
conforming to bh-audit-schema v1.1 for behavioral healthcare systems.
"""

__version__ = "0.4.0"

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
    OutcomeBlock,
    OutcomeStatus,
    ResourceBlock,
    ServiceBlock,
)
from bh_audit_logger._validation import AuditValidationError, validate_event_schema
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
    LoggingSink,
    MemorySink,
)
from bh_audit_logger.validation import ValidationError, validate_event, validate_event_minimal

__all__ = [
    "__version__",
    # Core
    "AuditLogger",
    "AuditLoggerConfig",
    "AuditStats",
    "EmitQueue",
    # Type definitions
    "ActionBlock",
    "ActionType",
    "ActorBlock",
    "ActorType",
    "AuditEvent",
    "CorrelationBlock",
    "DataClassification",
    "EmitFailureMode",
    "OutcomeBlock",
    "OutcomeStatus",
    "ResourceBlock",
    "ServiceBlock",
    # Sinks
    "AuditSink",
    "JsonlFileSink",
    "LoggingSink",
    "MemorySink",
    # Redaction utilities
    "contains_phi_tokens",
    "redact_tokens",
    "sanitize_error_message",
    # Validation
    "AuditValidationError",
    "ValidationError",
    "validate_event",
    "validate_event_minimal",
    "validate_event_schema",
]
