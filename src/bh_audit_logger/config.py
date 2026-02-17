"""
Configuration for AuditLogger.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass
class AuditLoggerConfig:
    """
    Configuration for AuditLogger.

    Args:
        service_name: Name of the service emitting events (required).
        service_environment: Deployment environment (default "unknown").
        service_version: Optional service version string.
        default_actor_id: Default actor subject_id when none is provided (default "unknown").
        default_actor_type: Default actor subject_type (default "service").
        metadata_allowlist: Set of metadata keys that are allowed. Empty means no metadata.
        sanitize_errors: Whether to sanitize error messages (default True).
        error_message_max_len: Maximum length for sanitized error messages (default 200).
        time_source: Callable returning current UTC datetime. Injectable for tests.
        id_factory: Callable returning a new event ID string. Injectable for tests.
        schema_version: Schema version to use (default "1.0").
    """

    service_name: str
    service_environment: str = "unknown"
    service_version: str | None = None
    default_actor_id: str = "unknown"
    default_actor_type: str = "service"
    metadata_allowlist: set[str] = field(default_factory=set)
    sanitize_errors: bool = True
    error_message_max_len: int = 200
    time_source: Callable[[], datetime] = field(default_factory=lambda: lambda: datetime.now(UTC))
    id_factory: Callable[[], str] = field(default_factory=lambda: lambda: str(uuid.uuid4()))
    schema_version: str = "1.0"
