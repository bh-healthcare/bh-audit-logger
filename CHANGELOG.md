# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-04-13

### Added

- **`AuditLogger.close()`** — flushes telemetry on Lambda exit or app shutdown.
  Blocking, bounded by `telemetry_http_timeout_s`.
- **Context manager** — `AuditLogger` now supports `with AuditLogger(config) as
  logger:` for automatic `close()` on exit.

### Changed

- **Lambda-safe telemetry** — telemetry system rewritten for ephemeral/serverless
  environments.  Dual-trigger flush (interval **or** event threshold, whichever comes
  first, default 300s / 500 events).  Mid-request flushes use a fire-and-forget daemon
  thread (zero added latency).  Disk-backed counter persistence survives cold starts.
  Failure logging raised from `DEBUG` to configurable `telemetry_log_level` (default
  `WARNING`).
- Five new `AuditLoggerConfig` fields: `telemetry_flush_interval_seconds`,
  `telemetry_event_flush_threshold`, `telemetry_log_level`,
  `telemetry_http_timeout_s`, `telemetry_flush_stale_on_init`.
- Updated `docs/telemetry.md` with Lambda configuration section, context manager
  usage, and cold-start latency guidance.

### Fixed

- **Telemetry payload format** — telemetry report now uses `"schema": "bh-telemetry-v1"`
  and nested `"period": {"start": ..., "end": ...}` to match the receiver Lambda API.
  The v1.0.0 format was silently rejected with HTTP 400; telemetry was never actually
  delivered.

## [1.0.0] - 2026-04-04

### Added

- **Verifier CLI** — `bh-audit verify` command for chain integrity verification.
  Supports `--source file` (JSONL) and `--source dynamodb` (DynamoDB table query),
  with `--format human` (default) and `--format json` (CI pipelines).
  Exit codes: 0 = PASS, 1 = FAIL, 2 = ERROR.
  Install with `pip install bh-audit-logger[cli]`.
- **Programmatic verifier** — `verify_chain()`, `VerifyResult`, `VerifyFailure`
  exported from top-level package for programmatic chain verification.
- **Opt-in telemetry** — privacy-first, counter-based weekly usage reports.
  No PII, no PHI, no event content. Off by default (`telemetry_enabled=False`).
  See `docs/telemetry.md`.
- **`[cli]` optional extra** — `typer>=0.9,<1` for the verifier CLI.
- **Documentation**: `docs/telemetry.md`, `docs/threat-model.md`,
  `docs/storage-patterns.md`.
- **Chain hashing (integrity)** — tamper-evident audit trails via SHA-256
  chain hashing.  Each event gets an `integrity` block with `event_hash`,
  `prev_event_hash`, and `hash_alg`.
  - `canonical_serialize()` — deterministic JSON serialization (sorted keys,
    compact separators, UTF-8, excludes `integrity` key).
  - `compute_chain_hash()` — computes integrity block from canonical bytes +
    optional previous hash.  Supports `sha256`, `sha384`, `sha512`.
  - `ChainState` — thread-safe, in-memory chain state for single-process
    deployments.  Tracks the most recent event hash for chaining.
  - `DynamoDBChainState` — multi-process safe chain state backed by a
    dedicated DynamoDB table with conditional writes.  Retries on conflict
    (up to 3 times), then falls back to unchained emission.
  - `LedgerSink` — JSONL file sink with built-in chain hashing.  Wraps
    `JsonlFileSink` + internal `ChainState` so every event written to disk
    includes an `integrity` block.
  - `enable_integrity` config flag on `AuditLoggerConfig` (default `False`).
    When enabled, `AuditLogger` injects integrity into every event before
    it reaches any sink (DynamoDB, JSONL, Logging, Memory, etc.).
  - `hash_algorithm` config field (`"sha256"` / `"sha384"` / `"sha512"`).
  - `AuditLogger` accepts optional `chain_state` parameter for resuming
    chains or sharing state across loggers.
  - `DynamoDBSink._flatten_for_dynamo` extracts `chain_hash` and
    `prev_chain_hash` from the `integrity` block into top-level DynamoDB
    attributes for direct querying.
  - New type exports: `HashAlgorithm`, `IntegrityBlock`.
- **DynamoDBSink** — new optional sink that writes audit events to a DynamoDB
  single-table design optimized for healthcare compliance queries. Requires
  `pip install bh-audit-logger[dynamodb]` (boto3).
  - Composite primary key (`service_name#date` / `timestamp#event_id`) for
    efficient time-range queries within a service.
  - Three Global Secondary Indexes: `patient_id-index` (HIPAA §164.312(b)
    access review), `actor-index` (§164.308(a)(1)(ii)(D) activity review),
    and `outcome-index` (access denial monitoring).
  - Query helpers: `query_by_patient()`, `query_by_actor()`, `query_denials()`
    with optional time-range filtering.
  - Configurable TTL (default 2190 days ≈ 6 years) for automatic retention
    management. Set `ttl_days=None` to disable.
  - `create_table=True` for dev/test table auto-creation with all GSIs.
  - Deduplication via `ConditionExpression` on `event_id` — duplicate writes
    are silently skipped.
  - Full event stored as compact JSON in `event_json` attribute; key fields
    flattened into top-level attributes for GSI projection.
- **`[dynamodb]` optional extra** — `boto3>=1.34,<2` for DynamoDB sink.
- **`[all]` convenience extra** — bundles `jsonschema`, `boto3`, and `typer`.
- **`docs/deploying-dynamodb.md`** — production deployment guide covering
  table creation (Terraform / AWS CLI), IAM minimum-privilege policy,
  environment variable configuration, retention strategy, capacity planning,
  failure handling, and monitoring checklist.
- **`integrity_events_total` / `chain_gaps_total` counters** on `AuditStats`
  — track successful integrity injections and chain computation failures.
- **`DynamoDBChainState.last_hash` property** — reads the current chain
  head from DynamoDB, matching the in-memory `ChainState` API.
- **`DynamoDBChainState.service_name` property** — exposes the partition
  key for inspection.
- **Algorithm validation** — `compute_chain_hash()` now raises `ValueError`
  for unsupported algorithms (only `sha256`, `sha384`, `sha512` allowed).
- **Double-hashing warning** — `LedgerSink.emit()` logs a warning if the
  event already contains an `integrity` block (possible double-hashing when
  `AuditLogger.enable_integrity` is also active).
- **`project.urls` Author link** — added `Author = "https://tanmayakumar.com"`
  to `pyproject.toml` for PyPI project page.

### Fixed

- **Critical: hash input order** — `compute_chain_hash()` now feeds
  `prev_hash` bytes before canonical bytes, matching the design doc and
  `bh-fastapi-audit`. Previous order (`canonical + prev_hash`) produced
  incompatible chain hashes.
- **`DynamoDBChainState` API alignment** — `service_name` moved from
  `advance()` parameter to constructor parameter (default `"default"`).
  `advance(event_hash)` signature now matches in-memory `ChainState`,
  making the two implementations interchangeable.
- **Chain state table billing mode** — `DynamoDBChainState._create_table`
  uses `BillingMode="PAY_PER_REQUEST"` instead of `ProvisionedThroughput`,
  matching the design doc and production best practice.
- **Integrity injection resilience** — `AuditLogger._safe_emit()` wraps
  chain hash computation in `try/except`. On failure, the event still emits
  (without integrity) and `chain_gaps_total` is incremented.
- **`ChainState` memory layout** — added `__slots__` for tighter memory.
- **Logging namespace** — chain state logging moved from `bh.audit.internal`
  to `bh.audit.chain` for easier filtering.

## [0.4.0] - 2026-03-30

### Added

- **Runtime schema validation** — new `validate_events` config flag enables
  validation of every emitted event against the vendored bh-audit-schema JSON
  schema before it reaches the sink. Requires the `[jsonschema]` optional extra.
- **`AuditValidationError`** — raised when `validation_failure_mode="raise"` and
  an event fails schema validation. Includes `event_id` and `errors` list.
- **`validate_event_schema()`** — list-returning validation API (returns error
  messages instead of raising). Exported from the top-level package.
- **Validation timing** — `AuditStats` tracks cumulative validation time via
  `validation_time_ms_total` counter and `record_validation_time()` method.
  Included in `snapshot()` output.
- **`audit_access_denied()`** — convenience method for emitting DENIED outcome
  events with `error_type` (e.g. `RoleDenied`, `CrossOrgAccessDenied`).
- **Schema version negotiation** — `target_schema_version` config field (default
  `"1.1"`) controls the `schema_version` in emitted events. When set to `"1.0"`,
  DENIED outcomes are automatically downgraded to FAILURE for backward compat.
- **Version-aware schema loading** — `load_schema()` and `get_schema_path()` now
  accept a `version` parameter. Vendored v1.0 schema added alongside v1.1.
- **Example events** — four JSON examples in `examples/` demonstrating batch
  export, worker read, role-based denial, and cross-org access denial.
- **Migration guide** — `docs/migrating-1.0-to-1.1.md` covering all schema
  changes and logger upgrade steps.

### Changed

- **`schema_version` config renamed to `target_schema_version`** — the new name
  better reflects its purpose (selecting which schema version to target). Type
  narrowed to `Literal["1.0", "1.1"]`.
- `load_schema()` now uses `@lru_cache(maxsize=4)` keyed on version string.

### Compatibility

- **Breaking**: `schema_version` config field removed in favor of
  `target_schema_version`. Direct users of `config.schema_version` must update.
- `validate_events=True` requires `pip install bh-audit-logger[jsonschema]` —
  an `ImportError` is raised eagerly at config construction if missing.
- `AuditStats.snapshot()` return type widened to `dict[str, int | float]` to
  accommodate `validation_time_ms_total`.

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

[1.1.0]: https://github.com/bh-healthcare/bh-audit-logger/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/bh-healthcare/bh-audit-logger/compare/v0.4.0...v1.0.0
[0.4.0]: https://github.com/bh-healthcare/bh-audit-logger/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/bh-healthcare/bh-audit-logger/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/bh-healthcare/bh-audit-logger/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/bh-healthcare/bh-audit-logger/releases/tag/v0.1.0
