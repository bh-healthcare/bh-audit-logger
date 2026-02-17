# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned

- Non-blocking / async sink variants (v0.3)
- Additional sinks (S3, Kafka, etc.)

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

[Unreleased]: https://github.com/bh-healthcare/bh-audit-logger/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/bh-healthcare/bh-audit-logger/releases/tag/v0.1.0
