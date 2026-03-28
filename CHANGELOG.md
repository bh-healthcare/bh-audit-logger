# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-03-28

### Added

- **Non-blocking async emission** — new `EmitQueue` with configurable bounded
  `asyncio.Queue` (default 10 000 events). Events are enqueued without blocking;
  a background task drains the queue and forwards to the sink via
  `run_in_executor()`. When the queue is full, events are dropped and
  `events_dropped_total` is incremented.
- **Typed event blocks** — `TypedDict` definitions for all event sub-blocks
  (`ServiceBlock`, `ActorBlock`, `ActionBlock`, `ResourceBlock`, `OutcomeBlock`,
  `CorrelationBlock`, `IntegrityBlock`, `AuditEvent`) and `Literal` type aliases
  (`ActionType`, `ActorType`, `OutcomeStatus`, `DataClassification`). Exported
  from the top-level package for static checking.
- **Frozen config** — `AuditLoggerConfig` is now `@dataclass(frozen=True)` to
  prevent runtime mutation of security settings (e.g. `sanitize_errors`,
  `metadata_allowlist`). `metadata_allowlist` uses `frozenset` for immutability.
- **Schema validation CI test** — `test_schema_validation.py` validates emitted
  events against the vendored bh-audit-schema v1.1 JSON schema.
- **v1.1 FAILURE compliance** — string errors now emit `error_type: "ApplicationError"`
  to satisfy the v1.1 conditional requirement that FAILURE outcomes always include
  both `error_type` and `error_message`.
- **v1.1 minimal validation** — `validate_event_minimal()` now checks nested
  required fields (`service.name`, `actor.subject_id`, `actor.subject_type`,
  `outcome.status`) and enforces the FAILURE/DENIED conditional rules.
- `MemorySink` now accepts optional `maxlen` parameter to bound memory growth.
- `default_actor_type` now uses `Literal["human", "service"]` type.
- `schema_version` config field now typed as `Literal["1.1"]`.
- `validate_event_minimal()` now validates UUIDs with strict `8-4-4-4-12` pattern.

### Changed

- **Schema version bumped to 1.1** — vendored bh-audit-schema v1.1 with HIPAA/SOC
  compliance rule set, DENIED outcome status, conditional FAILURE validation,
  maxLength/minLength bounds on all string fields, and scalar-only metadata.
- `schema_version` config default updated from `"1.0"` to `"1.1"`.
- `schema/__init__.py` now uses `@lru_cache` for `load_schema()` to avoid
  repeated disk reads.
- `MemorySink` is now thread-safe with internal locking.
- `MemorySink.events` is now a property returning a snapshot (list copy).
- `validate_event_minimal()` accepts both `"1.0"` and `"1.1"` schema versions.

### Fixed

- **Timestamp format** — uses `strftime` instead of fragile `.replace("+00:00", "Z")`.
- **String error missing error_type** — when `error` was a string (not an Exception),
  `_build_outcome` omitted `error_type`, producing schema-invalid FAILURE events.
  Now defaults to `"ApplicationError"`.
- **UUID validation tightened** — `validate_event_minimal()` now uses strict
  `8-4-4-4-12` UUID regex instead of overly permissive 16+ hex chars pattern.

### Compatibility

- Python 3.11+ unchanged
- **Breaking**: `AuditLoggerConfig` is now frozen — attribute assignment after creation raises.
- **Breaking**: `metadata_allowlist` is now `frozenset[str]` instead of `set[str]`.
- **Breaking**: `schema_version` default changed from `"1.0"` to `"1.1"`.
- `MemorySink.events` is now a property (list copy) instead of a direct attribute.

## [0.2.0] - 2026-03-11

### Added

- **Sink failure isolation** — new `emit_failure_mode` config (`"silent"`, `"log"`, `"raise"`)
  controls what happens when a sink raises during emission. Default `"log"` ensures audit
  failures never break application logic while still surfacing diagnostics.
- **Internal counters** — thread-safe `AuditStats` with `events_emitted_total`,
  `emit_failures_total`, `events_dropped_total`, `validation_failures_total`.
  Access via `logger.stats.snapshot()`.
- **Metadata string truncation** — long metadata string values are truncated to
  `max_metadata_value_length` (default 200) with a trailing `"..."`.
- New config fields on `AuditLoggerConfig`:
  - `emit_failure_mode: Literal["silent", "log", "raise"]` (default `"log"`)
  - `failure_logger_name: str` (default `"bh.audit.internal"`)
  - `max_metadata_value_length: int` (default `200`)
- `AuditStats` exported from package top level

### Changed

- `AuditLogger.emit()` and `AuditLogger.audit()` now use safe emission wrapper
  instead of calling `sink.emit()` directly
- Compact internal failure logs include only `event_id`, `service.name`,
  `action.type`, `resource.type` — never the full event payload
- `AuditStats.increment()` uses `Literal` type for counter names — typos are
  now caught by type checkers instead of raising `AttributeError` at runtime

### Fixed

- **ValidationError bypasses failure isolation** — `_prepare()` raised uncaught
  `ValidationError` that crashed callers even under `emit_failure_mode="silent"`.
  Now wrapped in the same failure-isolation path; increments
  `validation_failures_total` and `events_dropped_total`.
- **Dead counters** — `validation_failures_total` and `events_dropped_total` are
  now correctly incremented when validation fails or events are silently dropped.
- **Success counter in wrong position** — `events_emitted_total` was incremented
  inside the `try` block after `sink.emit()`; now in `else` clause so a counter
  error cannot be misattributed as a sink failure.
- **Email redaction regex** — `[A-Z|a-z]` contained a literal `|` in the character
  class; fixed to `[A-Za-z]`.

### Compatibility

- Python 3.11+ unchanged
- No breaking changes to existing public API
- Synchronous emission remains the default in v0.2.x

## [0.1.0] - 2026-02-17

### Added

- `AuditLogger` — core class for building and emitting audit events
  - `audit()` method builds event dict with all required fields and emits via sink
  - `emit()` method for pre-built event dicts with validation + sanitization
  - Convenience helpers: `audit_login_success()`, `audit_login_failure()`, `audit_access()`
- `AuditLoggerConfig` — configuration dataclass
  - Injectable `time_source` and `id_factory` for deterministic testing
  - `metadata_allowlist` for strict metadata filtering
  - `sanitize_errors` and `error_message_max_len` for PHI-safe error handling
- `AuditSink` — protocol for pluggable audit event sinks
- Pluggable sinks:
  - `LoggingSink` — emits one compact JSON line per event via Python logging (stdout-friendly)
  - `JsonlFileSink` — JSON Lines file sink, thread-safe, configurable flush
  - `MemorySink` — in-memory sink for testing
- Validation:
  - `validate_event_minimal()` — always-on minimal validation (required keys, schema_version, UUID, ISO timestamp)
  - `validate_event()` — optional full JSON schema validation (requires `[jsonschema]` extra)
  - Vendored bh-audit-schema v1.0 JSON schema for offline validation
- PHI redaction utilities:
  - `sanitize_error_message()` — redacts SSN, email, phone patterns; normalizes whitespace; truncates
  - `contains_phi_tokens()` — test utility for asserting PHI absence
  - `redact_tokens()` — explicit token redaction
- Metadata allowlist: only keys in `metadata_allowlist` pass through; non-scalar values silently dropped

### PHI Safety

- Error messages sanitized by default (SSN/email/phone patterns redacted, length capped)
- Metadata strictly allowlisted (empty set = no metadata)
- PHI safety enforced by comprehensive test suite with synthetic tokens

### Schema Conformance

- Events conform to bh-audit-schema v1.0
- All required fields populated: schema_version, event_id, timestamp, service, actor, action, resource, outcome

[Unreleased]: https://github.com/bh-healthcare/bh-audit-logger/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/bh-healthcare/bh-audit-logger/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/bh-healthcare/bh-audit-logger/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/bh-healthcare/bh-audit-logger/releases/tag/v0.1.0
