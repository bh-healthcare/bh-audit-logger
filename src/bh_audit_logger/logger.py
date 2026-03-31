"""
Core AuditLogger class.

Builds and emits PHI-safe audit events conforming to bh-audit-schema v1.1.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from bh_audit_logger._stats import AuditStats
from bh_audit_logger._types import (
    ActionBlock,
    ActionType,
    ActorBlock,
    AuditEvent,
    DataClassification,
    OutcomeBlock,
    ServiceBlock,
)
from bh_audit_logger.config import AuditLoggerConfig
from bh_audit_logger.redaction import sanitize_error_message
from bh_audit_logger.sinks.base import AuditSink
from bh_audit_logger.sinks.logging_sink import LoggingSink
from bh_audit_logger.validation import validate_event_minimal

_log = logging.getLogger(__name__)

_SCALAR_TYPES = (str, int, float, bool, type(None))


class AuditLogger:
    """Emit PHI-safe audit events conforming to bh-audit-schema v1.1.

    Events are built as typed dicts, validated for required fields,
    then forwarded to a pluggable sink (default: LoggingSink).

    Args:
        config: AuditLoggerConfig with service identity and behaviour settings.
        sink: An AuditSink implementation. Defaults to LoggingSink.
    """

    def __init__(
        self,
        config: AuditLoggerConfig,
        sink: AuditSink | None = None,
    ) -> None:
        self._config = config
        self._sink: AuditSink = sink if sink is not None else LoggingSink()
        self._stats = AuditStats()
        self._failure_log = logging.getLogger(config.failure_logger_name)

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

    @property
    def stats(self) -> AuditStats:
        """Return the internal emission counters."""
        return self._stats

    # ------------------------------------------------------------------
    # Safe emission
    # ------------------------------------------------------------------

    _PROGRAMMING_ERRORS = (TypeError, AttributeError, KeyError, RecursionError)

    def _safe_emit(self, event: dict[str, Any]) -> None:
        """Emit via sink with failure isolation governed by config.

        Clear programming errors (TypeError, AttributeError, KeyError,
        RecursionError) always propagate so bugs in custom sinks are
        surfaced immediately.  All other exceptions are routed through
        the configured failure mode.
        """
        if self._config.validate_events:
            from bh_audit_logger._validation import AuditValidationError, validate_event_schema

            try:
                t0 = time.perf_counter()
                errors = validate_event_schema(event, self._config.target_schema_version)
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                self._stats.record_validation_time(elapsed_ms)
            except self._PROGRAMMING_ERRORS:
                raise
            except Exception as exc:
                self._stats.increment("emit_failures_total")
                self._handle_failure(
                    "Audit schema validation error: event_id=%s service=%s action=%s "
                    "resource=%s error=%s",
                    event,
                    exc,
                )
                return

            if errors:
                mode = self._config.validation_failure_mode
                if mode == "raise":
                    raise AuditValidationError(event.get("event_id", "unknown"), errors)

                self._stats.increment("validation_failures_total")
                preview = errors[:3]
                self._failure_log.warning(
                    "Audit schema validation failed: event_id=%s service=%s action=%s "
                    "resource=%s errors=%s",
                    event.get("event_id"),
                    event.get("service", {}).get("name"),
                    event.get("action", {}).get("type"),
                    event.get("resource", {}).get("type"),
                    preview,
                )

                if mode == "log_and_emit":
                    pass  # fall through to emit below
                else:
                    self._stats.increment("events_dropped_total")
                    return

        try:
            self._sink.emit(event)
        except self._PROGRAMMING_ERRORS:
            raise
        except Exception as exc:
            self._stats.increment("emit_failures_total")
            self._handle_failure(
                "Audit sink emit failed: event_id=%s service=%s action=%s resource=%s error=%s",
                event,
                exc,
            )
        else:
            self._stats.increment("events_emitted_total")

    def _handle_failure(
        self,
        msg: str,
        event: dict[str, Any],
        exc: Exception,
    ) -> None:
        """Apply emit_failure_mode policy.

        - ``"raise"``: re-raise the exception.
        - ``"log"``: log at WARNING with compact summary.
        - ``"silent"``: log at DEBUG (never truly silent for HIPAA traceability).
        """
        mode = self._config.emit_failure_mode
        if mode == "raise":
            raise exc
        args = (
            event.get("event_id"),
            event.get("service", {}).get("name"),
            event.get("action", {}).get("type"),
            event.get("resource", {}).get("type"),
            exc,
        )
        if mode == "log":
            self._failure_log.warning(msg, *args)
        else:
            self._failure_log.debug(msg, *args)

    # ------------------------------------------------------------------
    # Core emit
    # ------------------------------------------------------------------

    def emit(self, event: dict[str, Any]) -> None:
        """Validate and emit a pre-built event dict.

        Applies metadata allowlist filtering, error sanitization,
        then forwards to the sink.  Validation failures are governed
        by ``emit_failure_mode`` (same as sink failures).
        """
        try:
            event = self._prepare(event)
        except Exception as exc:
            self._stats.increment("validation_failures_total")
            self._stats.increment("events_dropped_total")
            self._handle_failure(
                "Audit validation failed: event_id=%s service=%s action=%s resource=%s error=%s",
                event,
                exc,
            )
            return
        self._safe_emit(event)

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
        action_type: ActionType,
        *,
        actor: ActorBlock | dict[str, Any] | None = None,
        resource: dict[str, Any] | None = None,
        outcome: OutcomeBlock | dict[str, Any] | None = None,
        correlation: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        phi_touched: bool | None = None,
        data_classification: DataClassification | None = None,
        error: Exception | str | None = None,
    ) -> dict[str, Any] | None:
        """Build, emit, and return an audit event.

        Returns the emitted event dict on success, or ``None`` if the event
        was dropped due to validation failure.
        """
        cfg = self._config
        now = cfg.time_source()

        event: AuditEvent = {
            "schema_version": cfg.target_schema_version,
            "event_id": cfg.id_factory(),
            "timestamp": now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "service": self._build_service(),
            "actor": self._build_actor(actor),
            "action": self._build_action(
                action_type,
                phi_touched=phi_touched,
                data_classification=data_classification,
            ),
            "resource": resource or {"type": "unknown"},  # type: ignore[typeddict-item]
            "outcome": self._build_outcome(outcome, error),
        }

        if correlation:
            event["correlation"] = correlation  # type: ignore[typeddict-item]

        if metadata:
            event["metadata"] = metadata  # type: ignore[typeddict-item]

        try:
            prepared: dict[str, Any] = self._prepare(event)  # type: ignore[arg-type]
        except Exception as exc:
            self._stats.increment("validation_failures_total")
            self._stats.increment("events_dropped_total")
            self._handle_failure(
                "Audit validation failed: event_id=%s service=%s action=%s resource=%s error=%s",
                event,  # type: ignore[arg-type]
                exc,
            )
            return None
        self._safe_emit(prepared)
        return prepared

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    def audit_login_success(
        self,
        *,
        actor: ActorBlock | dict[str, Any] | None = None,
        resource: dict[str, Any] | None = None,
        correlation: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
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
        actor: ActorBlock | dict[str, Any] | None = None,
        resource: dict[str, Any] | None = None,
        error: Exception | str | None = None,
        correlation: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
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
        action_type: ActionType,
        *,
        actor: ActorBlock | dict[str, Any] | None = None,
        resource: dict[str, Any] | None = None,
        outcome: OutcomeBlock | dict[str, Any] | None = None,
        correlation: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        phi_touched: bool | None = None,
        data_classification: DataClassification | None = None,
        error: Exception | str | None = None,
    ) -> dict[str, Any] | None:
        """Emit a generic access event (READ / CREATE / UPDATE / DELETE)."""
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

    def audit_access_denied(
        self,
        action_type: ActionType,
        *,
        error_type: str = "AccessDenied",
        error_message: str | None = None,
        actor: ActorBlock | dict[str, Any] | None = None,
        resource: dict[str, Any] | None = None,
        correlation: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        phi_touched: bool | None = None,
        data_classification: DataClassification | None = None,
    ) -> dict[str, Any] | None:
        """Emit an access-denied audit event.

        Returns the emitted event dict on success, or ``None`` if the event
        was dropped due to validation failure (when validation_failure_mode
        is "drop" or "log_and_emit"). Callers should check for None if they
        need to confirm emission succeeded.
        """
        outcome: OutcomeBlock = {"status": "DENIED", "error_type": error_type}
        if error_message:
            outcome["error_message"] = error_message
        return self.audit(
            action_type,
            actor=actor,
            resource=resource,
            outcome=outcome,
            correlation=correlation,
            metadata=metadata,
            phi_touched=phi_touched,
            data_classification=data_classification,
        )

    # ------------------------------------------------------------------
    # Private builders
    # ------------------------------------------------------------------

    def _build_service(self) -> ServiceBlock:
        cfg = self._config
        svc: ServiceBlock = {
            "name": cfg.service_name,
            "environment": cfg.service_environment,
        }
        if cfg.service_version:
            svc["version"] = cfg.service_version
        return svc

    def _build_actor(self, actor: ActorBlock | dict[str, Any] | None) -> ActorBlock:
        cfg = self._config
        if actor:
            result = dict(actor)
            result.setdefault("subject_id", cfg.default_actor_id)
            result.setdefault("subject_type", cfg.default_actor_type)
            return result  # type: ignore[return-value]
        return {
            "subject_id": cfg.default_actor_id,
            "subject_type": cfg.default_actor_type,
        }

    def _build_action(
        self,
        action_type: ActionType,
        *,
        phi_touched: bool | None = None,
        data_classification: DataClassification | None = None,
    ) -> ActionBlock:
        action: ActionBlock = {"type": action_type}
        if phi_touched is not None:
            action["phi_touched"] = phi_touched
        action["data_classification"] = data_classification or "UNKNOWN"
        return action

    def _build_outcome(
        self,
        outcome: OutcomeBlock | dict[str, Any] | None,
        error: Exception | str | None,
    ) -> OutcomeBlock:
        """Build the outcome block.

        v1.1 conditional: FAILURE requires both error_type and error_message.
        When targeting v1.0, DENIED is downgraded to FAILURE with an
        error_message derived from the error_type.
        """
        if error is not None:
            error_msg = str(error)
            if self._config.sanitize_errors:
                error_msg = sanitize_error_message(
                    error_msg,
                    max_len=self._config.error_message_max_len,
                )
            error_type = (
                type(error).__name__ if isinstance(error, Exception) else "ApplicationError"
            )
            return {
                "status": "FAILURE",
                "error_type": error_type,
                "error_message": error_msg,
            }

        if outcome:
            result = dict(outcome)
            if "error_message" in result and self._config.sanitize_errors:
                result["error_message"] = sanitize_error_message(
                    result["error_message"],
                    max_len=self._config.error_message_max_len,
                )
            if self._config.target_schema_version == "1.0" and result.get("status") == "DENIED":
                result["status"] = "FAILURE"
                result.setdefault("error_message", result.get("error_type", "AccessDenied"))
            return result  # type: ignore[return-value]

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
                _log.warning("Dropping non-allowlisted metadata key: %s", key)
                continue
            if not isinstance(value, _SCALAR_TYPES):
                _log.warning(
                    "Dropping metadata key %s: value type %s is not a scalar",
                    key,
                    type(value).__name__,
                )
                continue
            max_len = self._config.max_metadata_value_length
            if isinstance(value, str) and len(value) > max_len:
                value = value[:max_len] + "..."
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
