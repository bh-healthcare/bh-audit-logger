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


_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

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

_SUPPORTED_SCHEMA_VERSIONS = frozenset({"1.0", "1.1"})


def validate_event_minimal(event: dict[str, Any]) -> None:
    """Perform minimal validation on an audit event.

    Checks:
    - All required top-level keys are present
    - schema_version is a supported version
    - event_id is a valid UUID (8-4-4-4-12 format)
    - timestamp looks like ISO 8601
    - Nested required fields: service.name, actor.subject_id,
      actor.subject_type, outcome.status

    Raises:
        ValidationError: If the event fails validation.
    """
    missing = _REQUIRED_TOP_LEVEL_KEYS - set(event.keys())
    if missing:
        raise ValidationError(f"Missing required keys: {sorted(missing)}")

    sv = event["schema_version"]
    if sv not in _SUPPORTED_SCHEMA_VERSIONS:
        raise ValidationError(
            f"Unsupported schema_version: {sv!r}"
            f" (expected one of {sorted(_SUPPORTED_SCHEMA_VERSIONS)})"
        )

    event_id = event["event_id"]
    if not isinstance(event_id, str) or not _UUID_RE.match(event_id):
        raise ValidationError(f"event_id is not a valid UUID: {event_id!r}")

    timestamp = event["timestamp"]
    if not isinstance(timestamp, str) or not _ISO_DATETIME.match(timestamp):
        raise ValidationError(f"timestamp does not look like ISO 8601: {timestamp!r}")

    service = event.get("service", {})
    if not isinstance(service, dict) or not service.get("name"):
        raise ValidationError("service.name is required and must be non-empty")

    actor = event.get("actor", {})
    if not isinstance(actor, dict):
        raise ValidationError("actor must be a dict")
    if not actor.get("subject_id"):
        raise ValidationError("actor.subject_id is required and must be non-empty")
    if not actor.get("subject_type"):
        raise ValidationError("actor.subject_type is required and must be non-empty")

    outcome = event.get("outcome", {})
    if not isinstance(outcome, dict) or not outcome.get("status"):
        raise ValidationError("outcome.status is required and must be non-empty")

    if outcome["status"] == "FAILURE":
        if not outcome.get("error_type"):
            raise ValidationError("outcome.error_type is required when outcome.status is FAILURE")
        if not outcome.get("error_message"):
            raise ValidationError(
                "outcome.error_message is required when outcome.status is FAILURE"
            )

    if outcome["status"] == "DENIED":
        if not outcome.get("error_type"):
            raise ValidationError("outcome.error_type is required when outcome.status is DENIED")


def validate_event(event: dict[str, Any]) -> None:
    """Validate an audit event against the vendored bh-audit-schema v1.1 JSON schema.

    Requires the ``jsonschema`` package
    (install with ``pip install bh-audit-logger[jsonschema]``).

    Raises:
        ValidationError: If the event fails validation.
        ImportError: If the jsonschema package is not installed.
    """
    try:
        import jsonschema
    except ImportError as exc:
        raise ImportError(
            "jsonschema is required for full schema validation. "
            "Install with: pip install bh-audit-logger[jsonschema]"
        ) from exc

    from bh_audit_logger.schema import load_schema

    schema = load_schema()
    try:
        jsonschema.validate(instance=event, schema=schema)
    except jsonschema.ValidationError as exc:
        raise ValidationError(str(exc.message)) from exc
