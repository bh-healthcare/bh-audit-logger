"""
Core AuditLogger class.

Builds and emits PHI-safe audit events conforming to bh-audit-schema v1.0.
"""

from __future__ import annotations

import logging
from typing import Any

from bh_audit_logger.config import AuditLoggerConfig
from bh_audit_logger.redaction import sanitize_error_message
from bh_audit_logger.sinks.base import AuditSink
from bh_audit_logger.sinks.logging_sink import LoggingSink
from bh_audit_logger.validation import validate_event_minimal

_log = logging.getLogger(__name__)

# JSON scalar types allowed in metadata values
_SCALAR_TYPES = (str, int, float, bool, type(None))


class AuditLogger:
    """
    Emit PHI-safe audit events conforming to bh-audit-schema v1.0.

    Events are built as plain dicts, validated for required fields,
    then forwarded to a pluggable sink (default: LoggingSink).

    Args:
        config: AuditLoggerConfig with service identity and behaviour settings.
        sink: An AuditSink implementation. Defaults to LoggingSink.

    Example::

        from bh_audit_logger import AuditLogger, AuditLoggerConfig

        logger = AuditLogger(
            config=AuditLoggerConfig(service_name="my-worker", service_environment="prod")
        )
        logger.audit(
            "READ",
            actor={"subject_id": "svc_etl", "subject_type": "service"},
            resource={"type": "Patient", "id": "pat_123"},
            outcome={"status": "SUCCESS"},
        )
    """

    def __init__(
        self,
        config: AuditLoggerConfig,
        sink: AuditSink | None = None,
    ) -> None:
        self._config = config
        self._sink: AuditSink = sink if sink is not None else LoggingSink()

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    @property
    def config(self) -> AuditLoggerConfig:
        """Return the current configuration."""
        return self._config

    @property
    def sink(self) -> AuditSink:
        """Return the current sink."""
        return self._sink

    # ------------------------------------------------------------------
    # Core emit
    # ------------------------------------------------------------------

    def emit(self, event: dict[str, Any]) -> None:
        """
        Validate and emit a pre-built event dict.

        Applies metadata allowlist filtering, error sanitization,
        then forwards to the sink.

        Args:
            event: A dict that should conform to bh-audit-schema v1.0.
        """
        event = self._prepare(event)
        self._sink.emit(event)

    def _prepare(self, event: dict[str, Any]) -> dict[str, Any]:
        """Apply allowlist, sanitization, and validation. Returns cleaned event."""
        event = self._apply_metadata_allowlist(event)
        event = self._apply_error_sanitization(event)
        validate_event_minimal(event)
        return event

    # ------------------------------------------------------------------
    # High-level audit builder
    # ------------------------------------------------------------------

    def audit(
        self,
        action_type: str,
        *,
        actor: dict[str, Any] | None = None,
        resource: dict[str, Any] | None = None,
        outcome: dict[str, Any] | None = None,
        correlation: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        phi_touched: bool | None = None,
        data_classification: str | None = None,
        error: Exception | str | None = None,
    ) -> dict[str, Any]:
        """
        Build, emit, and return an audit event.

        Args:
            action_type: Action type string (READ, CREATE, UPDATE, DELETE, LOGIN, etc.).
            actor: Actor dict with at least subject_id and subject_type.
            resource: Resource dict with at least type.
            outcome: Outcome dict with status (SUCCESS/FAILURE). Auto-built if error is set.
            correlation: Optional correlation dict (request_id, trace_id, etc.).
            metadata: Optional metadata dict (filtered by allowlist).
            phi_touched: Whether PHI was touched.
            data_classification: Data classification (PHI, PII, NONE, UNKNOWN).
            error: If set, outcome status is FAILURE and error message is sanitized.

        Returns:
            The emitted event dict.
        """
        cfg = self._config
        now = cfg.time_source()

        event: dict[str, Any] = {
            "schema_version": cfg.schema_version,
            "event_id": cfg.id_factory(),
            "timestamp": now.isoformat().replace("+00:00", "Z"),
            "service": self._build_service(),
            "actor": self._build_actor(actor),
            "action": self._build_action(
                action_type,
                phi_touched=phi_touched,
                data_classification=data_classification,
            ),
            "resource": resource or {"type": "unknown"},
            "outcome": self._build_outcome(outcome, error),
        }

        if correlation:
            event["correlation"] = correlation

        if metadata:
            event["metadata"] = metadata

        event = self._prepare(event)
        self._sink.emit(event)
        return event

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    def audit_login_success(
        self,
        *,
        actor: dict[str, Any] | None = None,
        resource: dict[str, Any] | None = None,
        correlation: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Emit a LOGIN / SUCCESS event."""
        return self.audit(
            "LOGIN",
            actor=actor,
            resource=resource or {"type": "Session"},
            outcome={"status": "SUCCESS"},
            correlation=correlation,
            metadata=metadata,
        )

    def audit_login_failure(
        self,
        *,
        actor: dict[str, Any] | None = None,
        resource: dict[str, Any] | None = None,
        error: Exception | str | None = None,
        correlation: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Emit a LOGIN / FAILURE event."""
        return self.audit(
            "LOGIN",
            actor=actor,
            resource=resource or {"type": "Session"},
            error=error or "Login failed",
            correlation=correlation,
            metadata=metadata,
        )

    def audit_access(
        self,
        action_type: str,
        *,
        actor: dict[str, Any] | None = None,
        resource: dict[str, Any] | None = None,
        outcome: dict[str, Any] | None = None,
        correlation: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        phi_touched: bool | None = None,
        data_classification: str | None = None,
        error: Exception | str | None = None,
    ) -> dict[str, Any]:
        """
        Emit a generic access event (READ / CREATE / UPDATE / DELETE).

        Convenience wrapper around audit() for common CRUD patterns.
        """
        return self.audit(
            action_type,
            actor=actor,
            resource=resource,
            outcome=outcome,
            correlation=correlation,
            metadata=metadata,
            phi_touched=phi_touched,
            data_classification=data_classification,
            error=error,
        )

    # ------------------------------------------------------------------
    # Private builders
    # ------------------------------------------------------------------

    def _build_service(self) -> dict[str, Any]:
        """Build the service block."""
        cfg = self._config
        svc: dict[str, Any] = {
            "name": cfg.service_name,
            "environment": cfg.service_environment,
        }
        if cfg.service_version:
            svc["version"] = cfg.service_version
        return svc

    def _build_actor(self, actor: dict[str, Any] | None) -> dict[str, Any]:
        """Build the actor block, applying defaults if needed."""
        cfg = self._config
        if actor:
            result = dict(actor)
            result.setdefault("subject_id", cfg.default_actor_id)
            result.setdefault("subject_type", cfg.default_actor_type)
            return result
        return {
            "subject_id": cfg.default_actor_id,
            "subject_type": cfg.default_actor_type,
        }

    def _build_action(
        self,
        action_type: str,
        *,
        phi_touched: bool | None = None,
        data_classification: str | None = None,
    ) -> dict[str, Any]:
        """Build the action block."""
        action: dict[str, Any] = {"type": action_type}
        if phi_touched is not None:
            action["phi_touched"] = phi_touched
        action["data_classification"] = data_classification or "UNKNOWN"
        return action

    def _build_outcome(
        self,
        outcome: dict[str, Any] | None,
        error: Exception | str | None,
    ) -> dict[str, Any]:
        """Build the outcome block."""
        if error is not None:
            error_msg = str(error)
            if self._config.sanitize_errors:
                error_msg = sanitize_error_message(
                    error_msg,
                    max_len=self._config.error_message_max_len,
                )
            result: dict[str, Any] = {
                "status": "FAILURE",
                "error_message": error_msg,
            }
            if isinstance(error, Exception):
                result["error_type"] = type(error).__name__
            return result

        if outcome:
            result = dict(outcome)
            if "error_message" in result and self._config.sanitize_errors:
                result["error_message"] = sanitize_error_message(
                    result["error_message"],
                    max_len=self._config.error_message_max_len,
                )
            return result

        return {"status": "SUCCESS"}

    # ------------------------------------------------------------------
    # Filtering
    # ------------------------------------------------------------------

    def _apply_metadata_allowlist(self, event: dict[str, Any]) -> dict[str, Any]:
        """Filter metadata to only allowed keys with scalar values."""
        raw_meta = event.get("metadata")
        if raw_meta is None:
            return event

        allowlist = self._config.metadata_allowlist
        if not allowlist:
            event = dict(event)
            event.pop("metadata", None)
            return event

        filtered: dict[str, Any] = {}
        for key, value in raw_meta.items():
            if key not in allowlist:
                _log.debug("Dropping non-allowlisted metadata key: %s", key)
                continue
            if not isinstance(value, _SCALAR_TYPES):
                _log.debug(
                    "Dropping metadata key %s: value type %s is not a scalar",
                    key,
                    type(value).__name__,
                )
                continue
            filtered[key] = value

        event = dict(event)
        if filtered:
            event["metadata"] = filtered
        else:
            event.pop("metadata", None)

        return event

    def _apply_error_sanitization(self, event: dict[str, Any]) -> dict[str, Any]:
        """Sanitize error_message in outcome if present."""
        outcome = event.get("outcome")
        if not outcome or "error_message" not in outcome:
            return event

        if not self._config.sanitize_errors:
            return event

        event = dict(event)
        event["outcome"] = dict(outcome)
        event["outcome"]["error_message"] = sanitize_error_message(
            outcome["error_message"],
            max_len=self._config.error_message_max_len,
        )
        return event
