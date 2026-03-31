"""
Runtime validation of audit events against bh-audit-schema.

Provides a list-returning API (unlike validation.py which raises).
Requires the [jsonschema] optional extra.
"""

from __future__ import annotations

import logging
import threading
from typing import Any

_logger = logging.getLogger("bh.audit.validation")

_validators: dict[str, Any] = {}
_validators_lock = threading.Lock()


class AuditValidationError(Exception):
    """Raised when an audit event fails schema validation (raise mode)."""

    def __init__(self, event_id: str, errors: list[str]) -> None:
        self.event_id = event_id
        self.errors = errors
        super().__init__(f"Audit event {event_id} failed validation: {'; '.join(errors)}")


def _get_validator(schema_version: str = "1.1") -> Any:
    """Load and cache a JSON Schema validator for the given version."""
    if schema_version in _validators:
        return _validators[schema_version]
    with _validators_lock:
        if schema_version not in _validators:
            try:
                from jsonschema import Draft202012Validator, FormatChecker
            except ImportError as exc:
                raise ImportError(
                    "jsonschema is required for runtime schema validation. "
                    "Install with: pip install bh-audit-logger[jsonschema]"
                ) from exc

            from bh_audit_logger.schema import load_schema

            schema = load_schema(schema_version)
            _validators[schema_version] = Draft202012Validator(
                schema, format_checker=FormatChecker()
            )
    return _validators[schema_version]


def validate_event_schema(event: dict[str, Any], schema_version: str = "1.1") -> list[str]:
    """Validate an audit event against the vendored schema.

    Returns a list of validation error messages. Empty list means valid.
    """
    validator = _get_validator(schema_version)
    errors: list[str] = []
    for error in validator.iter_errors(event):
        path = ".".join(str(p) for p in error.absolute_path)
        if path:
            errors.append(f"{path}: {error.message}")
        else:
            errors.append(error.message)
    return errors
