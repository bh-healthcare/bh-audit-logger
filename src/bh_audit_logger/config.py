"""
Configuration for AuditLogger.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Literal

from bh_audit_logger.schema import SCHEMA_VERSION as _SCHEMA_VERSION

_log = logging.getLogger("bh.audit.internal")


@dataclass(frozen=True)
class AuditLoggerConfig:
    """Immutable configuration for AuditLogger.

    Frozen after creation to prevent runtime mutation of security settings
    (e.g. ``sanitize_errors``, ``metadata_allowlist``).

    Raises ``ValueError`` at construction if ``service_name`` is empty or
    numeric constraints are violated.
    """

    service_name: str
    service_environment: str = "unknown"
    service_version: str | None = None
    default_actor_id: str = "unknown"
    default_actor_type: Literal["human", "service"] = "service"
    metadata_allowlist: frozenset[str] = field(default_factory=frozenset)
    sanitize_errors: bool = True
    error_message_max_len: int = 200
    emit_failure_mode: Literal["silent", "log", "raise"] = "log"
    failure_logger_name: str = "bh.audit.internal"
    max_metadata_value_length: int = 200
    time_source: Callable[[], datetime] = field(default_factory=lambda: lambda: datetime.now(UTC))
    id_factory: Callable[[], str] = field(default_factory=lambda: lambda: str(uuid.uuid4()))
    schema_version: str = _SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not self.service_name or not self.service_name.strip():
            raise ValueError("service_name must be a non-empty string")
        if self.error_message_max_len < 10:
            raise ValueError(
                f"error_message_max_len must be >= 10, got {self.error_message_max_len}"
            )
        if self.max_metadata_value_length < 1:
            raise ValueError(
                f"max_metadata_value_length must be >= 1, got {self.max_metadata_value_length}"
            )
        if isinstance(self.metadata_allowlist, set):
            object.__setattr__(self, "metadata_allowlist", frozenset(self.metadata_allowlist))
        if self.emit_failure_mode == "silent":
            _log.warning(
                "emit_failure_mode='silent' configured for service '%s'. "
                "Audit failures will be logged at DEBUG level only. "
                "Consider 'log' for production HIPAA deployments.",
                self.service_name,
            )
