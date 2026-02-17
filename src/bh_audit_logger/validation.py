"""
Event validation utilities.

Provides both minimal always-on validation and optional full JSON schema
validation (requires the [jsonschema] extra).
"""

from __future__ import annotations

import re
from typing import Any


class ValidationError(Exception):
    """Raised when an audit event fails validation."""


# UUID-like pattern: at least 16 hex-ish characters, dashes optional
_UUID_LIKE = re.compile(r"^[0-9a-fA-F\-]{16,}$")

# ISO 8601 date-time pattern (loose check, not a full parser)
_ISO_DATETIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")

_REQUIRED_TOP_LEVEL_KEYS = {
    "schema_version",
    "event_id",
    "timestamp",
    "service",
    "actor",
    "action",
    "resource",
    "outcome",
}


def validate_event_minimal(event: dict[str, Any]) -> None:
    """
    Perform minimal validation on an audit event.

    Checks:
    - All required top-level keys are present
    - schema_version is "1.0"
    - event_id looks UUID-like (>= 16 hex chars)
    - timestamp looks like ISO 8601

    Args:
        event: The audit event dictionary.

    Raises:
        ValidationError: If the event fails validation.
    """
    missing = _REQUIRED_TOP_LEVEL_KEYS - set(event.keys())
    if missing:
        raise ValidationError(f"Missing required keys: {sorted(missing)}")

    if event["schema_version"] != "1.0":
        raise ValidationError(
            f"Unsupported schema_version: {event['schema_version']!r} (expected '1.0')"
        )

    event_id = event["event_id"]
    if not isinstance(event_id, str) or not _UUID_LIKE.match(event_id):
        raise ValidationError(f"event_id does not look UUID-like: {event_id!r}")

    timestamp = event["timestamp"]
    if not isinstance(timestamp, str) or not _ISO_DATETIME.match(timestamp):
        raise ValidationError(f"timestamp does not look like ISO 8601: {timestamp!r}")


def validate_event(event: dict[str, Any]) -> None:
    """
    Validate an audit event against the vendored bh-audit-schema v1.0 JSON schema.

    Requires the ``jsonschema`` package (install with ``pip install bh-audit-logger[jsonschema]``).

    Args:
        event: The audit event dictionary.

    Raises:
        ValidationError: If the event fails validation.
        ImportError: If the jsonschema package is not installed.
    """
    try:
        import jsonschema
    except ImportError:
        raise ImportError(
            "jsonschema is required for full schema validation. "
            "Install with: pip install bh-audit-logger[jsonschema]"
        ) from None

    from bh_audit_logger.schema import load_schema

    schema = load_schema()
    try:
        jsonschema.validate(instance=event, schema=schema)
    except jsonschema.ValidationError as exc:
        raise ValidationError(str(exc.message)) from exc
