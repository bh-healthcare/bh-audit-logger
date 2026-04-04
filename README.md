# bh-audit-logger

Cloud-agnostic Python utilities for emitting **privacy-preserving audit events** for behavioral healthcare systems.

Events conform to **bh-audit-schema v1.1**:
https://github.com/bh-healthcare/bh-audit-schema

## Why

Audit logging in healthcare is often inconsistent across services and jobs.
This library provides a small, boring, correct baseline for emitting structured audit events from **any Python code** — Lambdas, workers, CLIs, ETL jobs, cron scripts — without logging raw PHI.

It is **not tied to FastAPI** (see [bh-fastapi-audit](https://github.com/bh-healthcare/bh-fastapi-audit) for middleware-based logging).

## Install

```bash
pip install bh-audit-logger               # core (zero dependencies)
pip install bh-audit-logger[dynamodb]      # + DynamoDB sink (boto3)
pip install bh-audit-logger[cli]           # + bh-audit verify CLI (typer)
pip install bh-audit-logger[jsonschema]    # + runtime schema validation
pip install bh-audit-logger[all]           # everything
```

## Quickstart

```bash
pip install bh-audit-logger
```

```python
from bh_audit_logger import AuditLogger, AuditLoggerConfig

logger = AuditLogger(
    config=AuditLoggerConfig(
        service_name="sample-datalake",
        service_environment="prod",
    )
)

logger.audit(
    "READ",
    actor={"subject_id": "service_lambda", "subject_type": "service"},
    resource={"type": "Patient", "id": "patient_123"},
    outcome={"status": "SUCCESS"},
    correlation={"request_id": "req_abc"},
)
```

By default, events are emitted as **one compact JSON line** via Python logging (stdout-friendly).

### Example output

```json
{"schema_version":"1.1","event_id":"6d3f0f6b-0c1a-4b9f-9d6f-9f6f7f5b2b0a","timestamp":"2026-03-28T12:00:00.000Z","service":{"name":"sample-datalake","environment":"prod"},"actor":{"subject_id":"service_lambda","subject_type":"service"},"action":{"type":"READ","data_classification":"UNKNOWN"},"resource":{"type":"Patient","id":"patient_123"},"outcome":{"status":"SUCCESS"},"correlation":{"request_id":"req_abc"}}
```

## Production usage: container logging

```python
from bh_audit_logger import AuditLogger, AuditLoggerConfig, LoggingSink

logger = AuditLogger(
    config=AuditLoggerConfig(
        service_name="my-service",
        service_environment="prod",
    ),
    sink=LoggingSink(logger_name="bh.audit", level="INFO"),
)
```

Works anywhere stdout is collected: **CloudWatch**, **GCP Cloud Logging**, **Azure Monitor**, **Kubernetes logging pipelines**.

## Production hardening

### Frozen config

`AuditLoggerConfig` is frozen after creation (`@dataclass(frozen=True)`) to prevent runtime mutation of security settings:

```python
config = AuditLoggerConfig(
    service_name="my-service",
    metadata_allowlist=frozenset({"batch_id", "region"}),
)
config.sanitize_errors = False  # raises AttributeError
```

### Sink failure isolation

By default, sink failures are logged but never propagate to your application logic:

```python
config = AuditLoggerConfig(
    service_name="my-service",
    emit_failure_mode="log",       # "silent", "log" (default), or "raise"
    failure_logger_name="bh.audit.internal",
)
```

### Metadata restrictions

Metadata values are enforced to be scalar JSON types (`str`, `int`, `float`, `bool`, `None`). Dict, list, and tuple values are silently dropped. Long strings are truncated:

```python
config = AuditLoggerConfig(
    service_name="my-service",
    metadata_allowlist=frozenset({"batch_id", "region"}),
    max_metadata_value_length=200,
)
```

### Internal counters

Track emission health via lightweight counters:

```python
logger = AuditLogger(config=config)
# ... emit events ...
print(logger.stats.snapshot())
# {"events_emitted_total": 42, "emit_failures_total": 0, "events_dropped_total": 0,
#  "validation_failures_total": 0, "validation_time_ms_total": 0.0}
```

### Non-blocking async emission (optional)

v0.3 adds `EmitQueue` for async emission from async contexts:

```python
from bh_audit_logger import EmitQueue

queue = EmitQueue(sink, stats, maxsize=5000)
queue.start()
queue.enqueue(event)
# ... later ...
await queue.shutdown()
```

## Runtime schema validation

v0.4 adds optional runtime validation of emitted events against the vendored JSON schema. This catches schema-invalid events **before** they reach your sink.

```bash
pip install bh-audit-logger[jsonschema]
```

```python
from bh_audit_logger import AuditLogger, AuditLoggerConfig

logger = AuditLogger(
    config=AuditLoggerConfig(
        service_name="my-service",
        validate_events=True,                    # enable runtime validation
        validation_failure_mode="drop",          # "drop" (default), "log_and_emit", or "raise"
        target_schema_version="1.1",             # "1.0" or "1.1" (default)
    )
)
```

| Mode | Behavior |
|---|---|
| `"drop"` | Log warning, increment `validation_failures_total` + `events_dropped_total`, do not emit |
| `"log_and_emit"` | Log warning, increment `validation_failures_total`, emit anyway |
| `"raise"` | Raise `AuditValidationError` with the event_id and error list |

### Validation timing

Validation adds measurable latency. Track it via stats:

```python
stats = logger.stats.snapshot()
print(stats["validation_time_ms_total"])  # cumulative ms spent in schema validation
```

## DENIED outcomes

v0.4 adds `audit_access_denied()` for authorization denials (distinct from operational failures):

```python
logger.audit_access_denied(
    "READ",
    error_type="RoleDenied",
    error_message="Role 'viewer' lacks access to ClinicalNote",
    actor={"subject_id": "user-42", "subject_type": "human"},
    resource={"type": "ClinicalNote", "id": "note-555"},
)
```

### Cross-org access detection

Use `owner_org_id` in the actor block to flag cross-organization access attempts:

```python
logger.audit_access_denied(
    "EXPORT",
    error_type="CrossOrgAccessDenied",
    error_message="Actor org-200 cannot export resources owned by org-300",
    actor={
        "subject_id": "user-77",
        "subject_type": "human",
        "org_id": "org-200",
        "owner_org_id": "org-300",
    },
    resource={"type": "PatientRecord"},
)
```

## Schema version negotiation

Target a specific schema version for backward compatibility:

```python
config = AuditLoggerConfig(
    service_name="my-service",
    target_schema_version="1.0",  # emit v1.0-compatible events
)
```

When targeting v1.0, DENIED outcomes are automatically downgraded to FAILURE (since v1.0 does not support DENIED).

## Sinks

| Sink | Use case | Notes |
|---|---|---|
| `LoggingSink` *(default)* | Production | One compact JSON line per event via Python `logging`; stdout-friendly |
| `JsonlFileSink` | Local dev, demos | Appends to a `.jsonl` file; thread-safe, flush-on-write by default |
| `LedgerSink` | Tamper-evident files | JSONL file sink with built-in chain hashing (wraps `JsonlFileSink` + `ChainState`) |
| `DynamoDBSink` | Production (AWS) | Single-table DynamoDB design with 3 GSIs for HIPAA compliance queries. `pip install bh-audit-logger[dynamodb]` |
| `MemorySink` | Tests | Bounded optional (`maxlen`); use `len(sink)` and `sink.events` in assertions |

Pass any sink to `AuditLogger(config=..., sink=...)`. Omit `sink` to get `LoggingSink` by default.

For `DynamoDBSink` production deployment (table creation, IAM, environment configuration), see [docs/deploying-dynamodb.md](docs/deploying-dynamodb.md).

## Configuration

`AuditLoggerConfig` fields (frozen after creation):

| Field | Type | Default | Description |
|---|---|---|---|
| `service_name` | `str` | *required* | Name of the service emitting events |
| `service_environment` | `str` | `"unknown"` | Deployment environment (prod, staging, dev) |
| `service_version` | `str \| None` | `None` | Service version/build identifier |
| `default_actor_id` | `str` | `"unknown"` | Default actor when none provided |
| `default_actor_type` | `Literal["human", "service"]` | `"service"` | Default actor type |
| `metadata_allowlist` | `frozenset[str]` | `frozenset()` | Allowed metadata keys (empty = no metadata) |
| `sanitize_errors` | `bool` | `True` | Sanitize error messages (redact SSN/email/phone) |
| `error_message_max_len` | `int` | `200` | Max length for sanitized error messages |
| `emit_failure_mode` | `Literal` | `"log"` | How to handle sink failures |
| `time_source` | `Callable` | `utcnow` | Injectable time source for testing |
| `id_factory` | `Callable` | `uuid4` | Injectable ID factory for testing |
| `validate_events` | `bool` | `False` | Enable runtime JSON schema validation |
| `validation_failure_mode` | `Literal` | `"drop"` | How to handle validation failures: `"drop"`, `"log_and_emit"`, `"raise"` |
| `target_schema_version` | `Literal["1.0", "1.1"]` | `"1.1"` | Schema version for emitted events |
| `failure_logger_name` | `str` | `"bh.audit.internal"` | Logger name for internal diagnostics |
| `max_metadata_value_length` | `int` | `200` | Max string length for metadata values |
| `enable_integrity` | `bool` | `False` | Enable chain hashing on emitted events |
| `hash_algorithm` | `Literal["sha256", "sha384", "sha512"]` | `"sha256"` | Hash algorithm for chain hashing |
| `telemetry_enabled` | `bool` | `False` | Enable opt-in anonymous telemetry |
| `telemetry_endpoint` | `str` | `"https://…/v1/report"` | Telemetry receiver URL |
| `telemetry_deployment_id_path` | `str` | `"/tmp/bh-audit/"` | Directory for anonymous deployment ID file |

## Typed event blocks

v0.3+ exports `TypedDict` definitions for all event sub-blocks:

```python
from bh_audit_logger import (
    AuditEvent, ServiceBlock, ActorBlock, ActionBlock,
    ResourceBlock, OutcomeBlock, CorrelationBlock,
    ActionType, ActorType, OutcomeStatus, DataClassification,
)
```

## PHI-safe by default

- **No request/response bodies** — the library never tries to capture payloads
- **Metadata is opt-in and strictly allowlisted** — only keys in `metadata_allowlist` pass through; values must be scalar JSON types
- **Error messages are sanitized** — SSN, email, phone patterns are redacted and messages are length-capped
- **PHI safety is enforced by tests** that assert synthetic PHI tokens never appear in emitted events

## Schema conformance

All events conform to [bh-audit-schema v1.1](https://github.com/bh-healthcare/bh-audit-schema). The v1.1 schema adds:
- `DENIED` outcome status (for authorization denials)
- Conditional FAILURE validation (requires `error_type` + `error_message`)
- `maxLength`/`minLength` bounds on all string fields
- Scalar-only metadata enforcement

## Optional schema validation

```bash
pip install bh-audit-logger[jsonschema]
```

```python
from bh_audit_logger import validate_event

event = {...}
validate_event(event)  # raises ValidationError on failure
```

Validates against the vendored bh-audit-schema v1.1 JSON schema included in the package.

## Chain hashing (integrity)

v1.0 adds tamper-evident audit trails via SHA-256 chain hashing. Each event gets an `integrity` block with `event_hash`, `prev_event_hash`, and `hash_alg`:

```python
config = AuditLoggerConfig(
    service_name="my-service",
    enable_integrity=True,       # SHA-256 chain hashing
    hash_algorithm="sha256",     # or "sha384", "sha512"
)
logger = AuditLogger(config=config)
```

For DynamoDB-backed multi-process chain state:

```python
from bh_audit_logger import DynamoDBChainState

chain_state = DynamoDBChainState(table_name="bh_chain_state", service_name="my-service")
logger = AuditLogger(config=config, chain_state=chain_state)
```

## Verifier CLI

v1.0 adds `bh-audit verify` for chain integrity verification:

```bash
pip install bh-audit-logger[cli]

# Verify a JSONL ledger file
bh-audit verify --source file --path /var/log/audit/events.jsonl

# Verify from DynamoDB
bh-audit verify --source dynamodb --table bh_audit_events --service intake-api

# JSON output for CI pipelines
bh-audit verify --source file --path events.jsonl --format json
```

Exit codes: `0` = PASS, `1` = FAIL, `2` = ERROR.

Programmatic verification:

```python
from bh_audit_logger import verify_chain

result = verify_chain(events)
assert result.result == "PASS"
```

## Telemetry

v1.0 adds opt-in, privacy-first telemetry. **Off by default.** No PII, no PHI, no event content -- only aggregate counters.

```python
config = AuditLoggerConfig(
    service_name="my-service",
    telemetry_enabled=True,  # explicit opt-in required
)
```

See [docs/telemetry.md](docs/telemetry.md) for the full privacy commitment and payload format.

## Related projects

- **bh-audit-schema**: [github.com/bh-healthcare/bh-audit-schema](https://github.com/bh-healthcare/bh-audit-schema) — the schema standard
- **bh-fastapi-audit**: [github.com/bh-healthcare/bh-fastapi-audit](https://github.com/bh-healthcare/bh-fastapi-audit) — FastAPI middleware for automatic audit logging

## License

Apache 2.0
