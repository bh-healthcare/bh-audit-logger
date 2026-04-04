"""
Audit event sinks for bh-audit-logger.

Sinks are responsible for persisting or forwarding audit events.
"""

from __future__ import annotations

from bh_audit_logger.sinks.base import AuditSink
from bh_audit_logger.sinks.jsonl import JsonlFileSink
from bh_audit_logger.sinks.ledger import LedgerSink
from bh_audit_logger.sinks.logging_sink import LoggingSink
from bh_audit_logger.sinks.memory import MemorySink

__all__ = [
    "AuditSink",
    "DynamoDBSink",
    "JsonlFileSink",
    "LedgerSink",
    "LoggingSink",
    "MemorySink",
]

try:
    from bh_audit_logger.sinks.dynamodb import DynamoDBSink
except ImportError:
    pass


def __getattr__(name: str) -> object:
    if name == "DynamoDBSink":
        raise ImportError(
            "DynamoDBSink requires boto3. Install with: pip install bh-audit-logger[dynamodb]"
        )
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
