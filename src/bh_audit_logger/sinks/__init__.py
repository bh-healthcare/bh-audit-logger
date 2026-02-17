"""
Audit event sinks for bh-audit-logger.

Sinks are responsible for persisting or forwarding audit events.
"""

from bh_audit_logger.sinks.base import AuditSink
from bh_audit_logger.sinks.jsonl import JsonlFileSink
from bh_audit_logger.sinks.logging_sink import LoggingSink
from bh_audit_logger.sinks.memory import MemorySink

__all__ = [
    "AuditSink",
    "JsonlFileSink",
    "LoggingSink",
    "MemorySink",
]
