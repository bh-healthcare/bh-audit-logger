# bh-audit-logger

Cloud-agnostic Python utilities for emitting **PHI-safe audit events** for behavioral healthcare systems.

Events conform to **bh-audit-schema v1.0**:
https://github.com/bh-healthcare/bh-audit-schema

## Why

Audit logging in healthcare is often inconsistent across services and jobs.
This library provides a small, boring, correct baseline for emitting structured audit events from **any Python code** — Lambdas, workers, CLIs, ETL jobs, cron scripts — without logging raw PHI.

It is **not tied to FastAPI** (see [bh-fastapi-audit](https://github.com/bh-healthcare/bh-fastapi-audit) for middleware-based logging).

## Quickstart

```bash
pip install bh-audit-logger
```

```python
from bh_audit_logger import AuditLogger, AuditLoggerConfig

logger = AuditLogger(
    config=AuditLoggerConfig(
        service_name="overstory-datalake",
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
{"schema_version":"1.0","event_id":"6d3f0f6b-0c1a-4b9f-9d6f-9f6f7f5b2b0a","timestamp":"2026-02-17T12:00:00Z","service":{"name":"overstory-datalake","environment":"prod"},"actor":{"subject_id":"service_lambda","subject_type":"service"},"action":{"type":"READ","data_classification":"UNKNOWN"},"resource":{"type":"Patient","id":"patient_123"},"outcome":{"status":"SUCCESS"},"correlation":{"request_id":"req_abc"}}
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

### AWS Lambda / serverless

```python
import json
import logging
from bh_audit_logger import AuditLogger, AuditLoggerConfig, LoggingSink

# Configure root logger for structured JSON to stdout (CloudWatch picks this up)
logging.basicConfig(level=logging.INFO)

audit = AuditLogger(
    config=AuditLoggerConfig(
        service_name="patient-export-lambda",
        service_environment="prod",
        service_version="2026.02.17.1",
    ),
    sink=LoggingSink(logger_name="bh.audit", level="INFO"),
)

def handler(event, context):
    audit.audit_access(
        "EXPORT",
        actor={"subject_id": "service_lambda", "subject_type": "service"},
        resource={"type": "PatientExport", "id": event.get("export_id", "unknown")},
        phi_touched=True,
        data_classification="PHI",
        correlation={"request_id": context.aws_request_id},
    )
    # ... do work ...
```

Each invocation emits one compact JSON line to stdout. CloudWatch Logs, GCP Cloud Logging, and Azure Monitor all ingest it without additional configuration.

## Configuration

`AuditLoggerConfig` fields:

| Field | Type | Default | Description |
|---|---|---|---|
| `service_name` | `str` | *required* | Name of the service emitting events |
| `service_environment` | `str` | `"unknown"` | Deployment environment (prod, staging, dev) |
| `service_version` | `str \| None` | `None` | Service version/build identifier |
| `default_actor_id` | `str` | `"unknown"` | Default actor when none provided |
| `default_actor_type` | `str` | `"service"` | Default actor type (human/service) |
| `metadata_allowlist` | `set[str]` | `set()` | Allowed metadata keys (empty = no metadata) |
| `sanitize_errors` | `bool` | `True` | Sanitize error messages (redact SSN/email/phone) |
| `error_message_max_len` | `int` | `200` | Max length for sanitized error messages |
| `time_source` | `Callable` | `utcnow` | Injectable time source for testing |
| `id_factory` | `Callable` | `uuid4` | Injectable ID factory for testing |
| `schema_version` | `str` | `"1.0"` | Locked to 1.0 unless overridden |

## PHI-safe defaults

- **No request/response bodies** — the library never tries to capture payloads
- **Metadata is opt-in and strictly allowlisted** — only keys in `metadata_allowlist` pass through; values must be scalar JSON types (str, int, float, bool, null)
- **Error messages are sanitized** — SSN, email, phone patterns are redacted and messages are length-capped
- **PHI safety is enforced by tests** that assert synthetic PHI tokens never appear in emitted events

> **Important:** This library does not attempt to detect or remove PHI from user-supplied IDs or free-text fields beyond the configured allowlist and error-message sanitization. Treat resource IDs (e.g. `patient_id`) as sensitive and prefer surrogate identifiers wherever possible. The goal is *safe defaults*, not total PHI stripping.

### Do not do this

```python
# BAD: patient name in metadata
logger.audit("READ", resource={"type": "Patient"}, metadata={"patient_name": "Jane Doe"})

# BAD: full stack trace in error (may contain PHI from variables)
logger.audit("READ", resource={"type": "Patient"}, error=traceback.format_exc())

# BAD: MRN or SSN as a resource ID
logger.audit("READ", resource={"type": "Patient", "id": "123-45-6789"})
```

Instead, use surrogate IDs, keep metadata to operational keys (job name, batch ID, region), and let `sanitize_errors=True` (the default) handle error messages.

## Schema conformance

All events conform to [bh-audit-schema v1.0](https://github.com/bh-healthcare/bh-audit-schema). Required fields:

- `schema_version` = `"1.0"`
- `event_id` (UUID)
- `timestamp` (UTC ISO 8601)
- `service` (name, environment)
- `actor` (subject_id, subject_type)
- `action` (type)
- `resource` (type)
- `outcome` (status)

## Optional schema validation

```bash
pip install bh-audit-logger[jsonschema]
```

```python
from bh_audit_logger import validate_event

event = {...}
validate_event(event)  # raises ValidationError on failure
```

Validates against the vendored bh-audit-schema v1.0 JSON schema included in the package.

## Related projects

- **bh-audit-schema**: [github.com/bh-healthcare/bh-audit-schema](https://github.com/bh-healthcare/bh-audit-schema) — the schema standard
- **bh-fastapi-audit**: [github.com/bh-healthcare/bh-fastapi-audit](https://github.com/bh-healthcare/bh-fastapi-audit) — FastAPI middleware for automatic audit logging

## License

Apache 2.0
