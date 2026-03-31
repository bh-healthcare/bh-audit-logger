# Migrating from Schema 1.0 to 1.1

This guide covers what changed in bh-audit-schema v1.1 and how to update code that uses `bh-audit-logger`.

## Breaking changes in the schema

### FAILURE requires `error_type` + `error_message`

In v1.0, FAILURE outcomes only required `status`. In v1.1, both `error_type` and `error_message` are conditionally required whenever `outcome.status == "FAILURE"`.

**Before (v1.0):**

```python
logger.audit("READ", outcome={"status": "FAILURE"})
```

**After (v1.1):**

```python
logger.audit("READ", error=RuntimeError("Something went wrong"))
```

The logger's `_build_outcome()` automatically populates `error_type` (from the exception class name) and `error_message` (sanitized). If passing a string error, `error_type` defaults to `"ApplicationError"`.

### DENIED is new for authorization denials

v1.1 adds `DENIED` as a third outcome status for cases where the system intentionally refused access (not an error). `DENIED` requires `error_type` to categorize the denial.

```python
logger.audit_access_denied(
    "READ",
    error_type="RoleDenied",
    error_message="Role 'viewer' lacks access to ClinicalNote",
    actor={"subject_id": "user-42", "subject_type": "human"},
    resource={"type": "ClinicalNote"},
)
```

If your system targets v1.0 consumers, set `target_schema_version="1.0"` in config — the logger will automatically downgrade DENIED to FAILURE.

### Metadata must be scalar only

v1.1 enforces that metadata values are scalar types (`string`, `integer`, `number`, `boolean`, `null`). Nested objects and arrays are not allowed.

The logger already enforced this, so no code changes are needed if you were using `metadata_allowlist`.

### Correlation must be non-empty if present

If a `correlation` block is included, it must have at least one property (`request_id`, `trace_id`, or `session_id`). An empty `{}` correlation block fails v1.1 validation.

```python
# Don't do this:
logger.audit("READ", correlation={})

# Do this:
logger.audit("READ", correlation={"request_id": "req-abc"})
# Or omit correlation entirely if not needed
```

### String fields have length constraints

v1.1 adds `minLength` and `maxLength` constraints to all string fields:

| Field | Max Length |
|---|---|
| `service.name` | 128 |
| `service.environment` | 64 |
| `service.version` | 64 |
| `actor.subject_id` | 256 |
| `actor.org_id` | 128 |
| `actor.owner_org_id` | 128 |
| `correlation.*` | 256 |
| `resource.type` | 128 |
| `resource.id` | 256 |
| `outcome.error_type` | 128 |
| `outcome.error_message` | 500 |

The logger's `error_message_max_len` config (default 200) already truncates error messages well within the 500-char limit.

## New features in bh-audit-logger v0.4.0

### Runtime schema validation

Enable runtime validation of emitted events against the JSON schema:

```python
from bh_audit_logger import AuditLogger, AuditLoggerConfig

logger = AuditLogger(
    config=AuditLoggerConfig(
        service_name="my-service",
        validate_events=True,
        validation_failure_mode="drop",  # or "log_and_emit", "raise"
    )
)
```

Requires the `jsonschema` extra: `pip install bh-audit-logger[jsonschema]`

### Schema version negotiation

Target a specific schema version for backward compatibility:

```python
config = AuditLoggerConfig(
    service_name="my-service",
    target_schema_version="1.0",  # emit v1.0-compatible events
)
```

When targeting v1.0, DENIED outcomes are automatically downgraded to FAILURE.

### Validation timing

Track validation performance via the stats snapshot:

```python
stats = logger.stats.snapshot()
print(stats["validation_time_ms_total"])
```
