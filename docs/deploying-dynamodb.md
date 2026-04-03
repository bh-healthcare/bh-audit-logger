# Deploying DynamoDBSink to AWS

This guide covers everything needed to run `DynamoDBSink` in production: table setup, IAM permissions, environment configuration, retention, and operational monitoring.

## Table Design

`DynamoDBSink` uses a single-table design optimized for healthcare compliance query patterns.

**Primary key:**

| Key | Attribute | Format | Example |
|---|---|---|---|
| Partition (PK) | `service_date` | `{service_name}#{YYYY-MM-DD}` | `intake-api#2026-04-15` |
| Sort (SK) | `ts_event` | `{ISO timestamp}#{event_id}` | `2026-04-15T14:32:07.123Z#c1d2e3f4-...` |

This co-locates all events for a service on a given day, making time-range queries within a day efficient via the sort key.

**Global Secondary Indexes:**

| Index | Partition key | Sort key | Use case |
|---|---|---|---|
| `patient_id-index` | `patient_id` | `timestamp` | "All access to patient X in the last 90 days" (HIPAA §164.312(b)) |
| `actor-index` | `actor_subject_id` | `timestamp` | "All actions by user Y in the last 30 days" (HIPAA §164.308(a)(1)(ii)(D)) |
| `outcome-index` | `outcome_status` | `timestamp` | "All DENIED access attempts" (HIPAA §164.308(a)(5)(ii)(C)) |

## Creating the Table

### Option A: Terraform (recommended)

A ready-to-use Terraform module is provided in [`bh-audit-logger-examples/terraform/`](https://github.com/bh-healthcare/bh-audit-logger-examples/tree/main/terraform). It creates the table with production defaults: on-demand billing, encryption at rest, point-in-time recovery, and TTL.

```bash
cd bh-audit-logger-examples/terraform/
terraform init
terraform plan -var="environment=prod" -var="table_name=bh_audit_events"
terraform apply -var="environment=prod" -var="table_name=bh_audit_events"
```

### Option B: AWS CLI

```bash
aws dynamodb create-table \
  --table-name bh_audit_events \
  --billing-mode PAY_PER_REQUEST \
  --attribute-definitions \
    AttributeName=service_date,AttributeType=S \
    AttributeName=ts_event,AttributeType=S \
    AttributeName=patient_id,AttributeType=S \
    AttributeName=actor_subject_id,AttributeType=S \
    AttributeName=outcome_status,AttributeType=S \
    AttributeName=timestamp,AttributeType=S \
  --key-schema \
    AttributeName=service_date,KeyType=HASH \
    AttributeName=ts_event,KeyType=RANGE \
  --global-secondary-indexes \
    '[
      {
        "IndexName": "patient_id-index",
        "KeySchema": [
          {"AttributeName": "patient_id", "KeyType": "HASH"},
          {"AttributeName": "timestamp", "KeyType": "RANGE"}
        ],
        "Projection": {
          "ProjectionType": "INCLUDE",
          "NonKeyAttributes": ["event_id","action_type","actor_subject_id","outcome_status","data_classification","http_route_template","event_json"]
        }
      },
      {
        "IndexName": "actor-index",
        "KeySchema": [
          {"AttributeName": "actor_subject_id", "KeyType": "HASH"},
          {"AttributeName": "timestamp", "KeyType": "RANGE"}
        ],
        "Projection": {
          "ProjectionType": "INCLUDE",
          "NonKeyAttributes": ["event_id","action_type","resource_type","patient_id","outcome_status","http_route_template","event_json"]
        }
      },
      {
        "IndexName": "outcome-index",
        "KeySchema": [
          {"AttributeName": "outcome_status", "KeyType": "HASH"},
          {"AttributeName": "timestamp", "KeyType": "RANGE"}
        ],
        "Projection": {
          "ProjectionType": "INCLUDE",
          "NonKeyAttributes": ["event_id","actor_subject_id","action_type","resource_type","patient_id","error_type","event_json"]
        }
      }
    ]' \
  --sse-specification Enabled=true \
  --tags Key=Project,Value=bh-healthcare Key=Component,Value=audit-logger

# Enable TTL
aws dynamodb update-time-to-live \
  --table-name bh_audit_events \
  --time-to-live-specification "Enabled=true, AttributeName=ttl"

# Enable point-in-time recovery
aws dynamodb update-continuous-backups \
  --table-name bh_audit_events \
  --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true
```

### Option C: create_table=True (dev/test only)

For local development and testing, the sink can create the table automatically:

```python
sink = DynamoDBSink(table_name="bh_audit_events", create_table=True)
```

**Never use `create_table=True` in production.** It creates a provisioned-throughput table (5/5 RCU/WCU) without encryption, PITR, or TTL configuration. Production tables should be managed by IaC.

## IAM Permissions

The service running `DynamoDBSink` needs exactly three DynamoDB actions. This is the minimum-privilege IAM policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AuditEventWrite",
      "Effect": "Allow",
      "Action": [
        "dynamodb:PutItem"
      ],
      "Resource": [
        "arn:aws:dynamodb:REGION:ACCOUNT:table/bh_audit_events"
      ]
    },
    {
      "Sid": "AuditEventQuery",
      "Effect": "Allow",
      "Action": [
        "dynamodb:Query"
      ],
      "Resource": [
        "arn:aws:dynamodb:REGION:ACCOUNT:table/bh_audit_events",
        "arn:aws:dynamodb:REGION:ACCOUNT:table/bh_audit_events/index/*"
      ]
    },
    {
      "Sid": "AuditTableDescribe",
      "Effect": "Allow",
      "Action": [
        "dynamodb:DescribeTable"
      ],
      "Resource": [
        "arn:aws:dynamodb:REGION:ACCOUNT:table/bh_audit_events"
      ]
    }
  ]
}
```

Replace `REGION` and `ACCOUNT` with your AWS region and account ID. If you used the Terraform module, attach the output `iam_policy_arn` to your service role.

**What each permission does:**

| Action | Used by | Purpose |
|---|---|---|
| `PutItem` | `DynamoDBSink.emit()` | Write audit events |
| `Query` | `query_by_patient()`, `query_by_actor()`, `query_denials()` | Compliance queries via GSIs |
| `DescribeTable` | boto3 Table resource | Validate table exists at startup |

**If your service only writes (never queries)**, you can omit the `Query` statement entirely. The query helpers are optional and often run from a separate compliance/admin tool.

## Environment Configuration

`DynamoDBSink` accepts its configuration as constructor arguments. The recommended pattern is to source these from environment variables:

```python
import os
from bh_audit_logger import AuditLogger, AuditLoggerConfig
from bh_audit_logger.sinks.dynamodb import DynamoDBSink

sink = DynamoDBSink(
    table_name=os.environ.get("BH_AUDIT_TABLE", "bh_audit_events"),
    region=os.environ.get("BH_AUDIT_REGION"),       # None = boto3 default chain
    ttl_days=int(os.environ.get("BH_AUDIT_TTL_DAYS", "2190")) or None,
)

logger = AuditLogger(
    config=AuditLoggerConfig(
        service_name=os.environ.get("SERVICE_NAME", "my-service"),
        service_environment=os.environ.get("SERVICE_ENV", "prod"),
        emit_failure_mode="log",  # never crash on audit failure
    ),
    sink=sink,
)
```

**Environment variables reference:**

| Variable | Default | Description |
|---|---|---|
| `BH_AUDIT_TABLE` | `bh_audit_events` | DynamoDB table name |
| `BH_AUDIT_REGION` | (boto3 default) | AWS region for the table |
| `BH_AUDIT_TTL_DAYS` | `2190` (~6 years) | TTL in days; `0` disables TTL (items never expire) |
| `AWS_ACCESS_KEY_ID` | (from instance role) | AWS credentials (prefer IAM roles over keys) |
| `AWS_SECRET_ACCESS_KEY` | (from instance role) | AWS credentials |
| `AWS_DEFAULT_REGION` | — | Fallback region for boto3 |

In ECS, Lambda, or EKS, prefer **IAM task roles / execution roles** over access keys. The boto3 default credential chain will automatically use the role attached to the compute environment.

## Retention Strategy

### TTL-only (recommended starting point)

`DynamoDBSink` sets a `ttl` attribute on every event, defaulting to 2190 days (~6 years) from the event timestamp. DynamoDB automatically deletes expired items at no write cost.

```python
sink = DynamoDBSink(ttl_days=2190)   # 6-year HIPAA retention, then auto-delete
sink = DynamoDBSink(ttl_days=None)   # disable TTL (items never expire)
sink = DynamoDBSink(ttl_days=0)      # also disables TTL
```

### S3 archive (optional, for cost optimization)

For deployments that accumulate significant storage, archive older events to S3 before TTL expiration:

1. Run a periodic job (Lambda, cron) that queries events older than N days
2. Write them to S3 as gzipped JSONL: `s3://bucket/audit-archive/{service}/{year}/{month}/events.jsonl.gz`
3. S3 lifecycle rules move objects to Glacier after 1 year and delete after 6 years
4. Reduce the DynamoDB TTL to match the archive window (e.g., `ttl_days=90`)

This is not yet automated by `bh-audit-logger`. Implement it when monthly DynamoDB storage costs exceed your threshold.

## Capacity Planning

For a typical BH Healthcare deployment (100-500 patients):

| Metric | Estimate |
|---|---|
| Daily events | 500 - 2,000 |
| Average event size | ~1.5 KB |
| Daily storage | ~1 - 3 MB |
| Monthly storage | ~30 - 90 MB |
| 6-year retention | ~2 - 6.5 GB |
| Monthly cost (on-demand) | ~$1.50 at full retention |

On-demand billing (`PAY_PER_REQUEST`) is recommended. At this scale, costs are negligible and there is no capacity planning overhead. Switch to provisioned throughput only if you need reserved capacity pricing at higher volumes.

## Failure Handling

`DynamoDBSink` raises exceptions on write failures (throttling, network errors, permission denied). The `AuditLogger` failure isolation layer handles these based on `emit_failure_mode`:

| Mode | Behavior | Recommended for |
|---|---|---|
| `"log"` (default) | Log warning, continue | Production |
| `"silent"` | Log at DEBUG, continue | Background jobs where logs are noisy |
| `"raise"` | Re-raise exception | Testing, critical-path audit requirements |

In `"log"` mode, a failed DynamoDB write never breaks your application. The `AuditStats` counters track failures:

```python
stats = logger.stats.snapshot()
# stats["emit_failures_total"] -- number of failed writes
# stats["events_emitted_total"] -- number of successful writes
```

Surface these counters in your health-check endpoint or monitoring system.

## Monitoring Checklist

- [ ] CloudWatch alarm on `ConsumedWriteCapacityUnits` (if using provisioned throughput)
- [ ] CloudWatch alarm on `SystemErrors` and `UserErrors` for the table
- [ ] Application metric: `logger.stats.snapshot()["emit_failures_total"]` trending upward
- [ ] Periodic `bh-audit verify` run (Phase 3) to confirm chain integrity
- [ ] IAM Access Analyzer enabled on the AWS account to detect over-broad policies
