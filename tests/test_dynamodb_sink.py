"""
Tests for DynamoDBSink.

All tests use moto for DynamoDB mocking -- no real AWS calls are made.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

boto3 = pytest.importorskip("boto3")
moto = pytest.importorskip("moto")

from moto import mock_aws  # noqa: E402

from bh_audit_logger import AuditLogger, AuditLoggerConfig  # noqa: E402
from bh_audit_logger.sinks.dynamodb import DynamoDBSink  # noqa: E402

from .conftest import make_test_event  # noqa: E402

TABLE_NAME = "test_audit_events"
REGION = "us-east-1"


@pytest.fixture
def _aws_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Provide dummy AWS credentials for moto."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


@pytest.fixture
def dynamo_sink(_aws_env: None) -> DynamoDBSink:
    """Create a DynamoDBSink backed by moto with table auto-creation."""
    with mock_aws():
        sink = DynamoDBSink(
            table_name=TABLE_NAME,
            region=REGION,
            create_table=True,
        )
        yield sink


def _event_with_patient(**overrides: Any) -> dict[str, Any]:
    """Return a test event with a patient_id on the resource."""
    return make_test_event(
        resource={"type": "Patient", "patient_id": "pat_001", "id": "res_001"},
        **overrides,
    )


# ------------------------------------------------------------------
# Table creation
# ------------------------------------------------------------------


class TestTableCreation:
    def test_create_table_succeeds(self, _aws_env: None) -> None:
        with mock_aws():
            DynamoDBSink(table_name=TABLE_NAME, region=REGION, create_table=True)
            client = boto3.client("dynamodb", region_name=REGION)
            desc = client.describe_table(TableName=TABLE_NAME)
            table = desc["Table"]
            assert table["TableName"] == TABLE_NAME

            gsi_names = {g["IndexName"] for g in table["GlobalSecondaryIndexes"]}
            assert gsi_names == {"patient_id-index", "actor-index", "outcome-index"}

    def test_create_table_idempotent(self, _aws_env: None) -> None:
        with mock_aws():
            DynamoDBSink(table_name=TABLE_NAME, region=REGION, create_table=True)
            DynamoDBSink(table_name=TABLE_NAME, region=REGION, create_table=True)

    def test_table_name_property(self, dynamo_sink: DynamoDBSink) -> None:
        assert dynamo_sink.table_name == TABLE_NAME

    def test_endpoint_url_accepted(self, _aws_env: None) -> None:
        """endpoint_url parameter is threaded through to boto3.resource()."""
        with mock_aws():
            sink = DynamoDBSink(
                table_name=TABLE_NAME,
                region=REGION,
                endpoint_url="http://localhost:9999",
            )
            assert sink.table_name == TABLE_NAME
            assert sink._resource.meta.client._endpoint.host == "http://localhost:9999"


# ------------------------------------------------------------------
# Basic emit
# ------------------------------------------------------------------


class TestEmit:
    def test_emit_single_event(self, dynamo_sink: DynamoDBSink) -> None:
        event = _event_with_patient()
        dynamo_sink.emit(event)

        client = boto3.client("dynamodb", region_name=REGION)
        resp = client.scan(TableName=TABLE_NAME)
        assert resp["Count"] == 1

    def test_emit_stores_event_json(self, dynamo_sink: DynamoDBSink) -> None:
        event = _event_with_patient()
        dynamo_sink.emit(event)

        client = boto3.client("dynamodb", region_name=REGION)
        resp = client.scan(TableName=TABLE_NAME)
        item = resp["Items"][0]
        stored = json.loads(item["event_json"]["S"])
        assert stored["event_id"] == event["event_id"]
        assert stored["service"]["name"] == "test-service"

    def test_emit_multiple_events(self, dynamo_sink: DynamoDBSink) -> None:
        for i in range(5):
            event = make_test_event(
                event_id=f"00000000-0000-0000-0000-00000000000{i}",
                resource={"type": "Patient", "patient_id": f"pat_{i:03d}"},
            )
            dynamo_sink.emit(event)

        client = boto3.client("dynamodb", region_name=REGION)
        resp = client.scan(TableName=TABLE_NAME)
        assert resp["Count"] == 5


# ------------------------------------------------------------------
# Partition key strategy
# ------------------------------------------------------------------


class TestPartitionKey:
    def test_pk_is_service_name_hash_date(self, dynamo_sink: DynamoDBSink) -> None:
        event = make_test_event(timestamp="2026-04-15T14:32:07.123Z")
        dynamo_sink.emit(event)

        client = boto3.client("dynamodb", region_name=REGION)
        resp = client.scan(TableName=TABLE_NAME)
        item = resp["Items"][0]
        assert item["service_date"]["S"] == "test-service#2026-04-15"

    def test_sk_is_timestamp_hash_event_id(self, dynamo_sink: DynamoDBSink) -> None:
        event = make_test_event(timestamp="2026-04-15T14:32:07.123Z")
        dynamo_sink.emit(event)

        client = boto3.client("dynamodb", region_name=REGION)
        resp = client.scan(TableName=TABLE_NAME)
        item = resp["Items"][0]
        expected_sk = f"2026-04-15T14:32:07.123Z#{event['event_id']}"
        assert item["ts_event"]["S"] == expected_sk


# ------------------------------------------------------------------
# Deduplication
# ------------------------------------------------------------------


class TestDeduplication:
    def test_duplicate_event_id_does_not_overwrite(self, dynamo_sink: DynamoDBSink) -> None:
        event = make_test_event()
        dynamo_sink.emit(event)

        modified = make_test_event(
            outcome={"status": "FAILURE", "error_type": "Oops", "error_message": "boom"}
        )
        dynamo_sink.emit(modified)

        client = boto3.client("dynamodb", region_name=REGION)
        resp = client.scan(TableName=TABLE_NAME)
        assert resp["Count"] == 1
        stored = json.loads(resp["Items"][0]["event_json"]["S"])
        assert stored["outcome"]["status"] == "SUCCESS"


# ------------------------------------------------------------------
# TTL
# ------------------------------------------------------------------


class TestTTL:
    def test_ttl_set_by_default(self, dynamo_sink: DynamoDBSink) -> None:
        event = make_test_event(timestamp="2026-04-15T12:00:00.000Z")
        dynamo_sink.emit(event)

        client = boto3.client("dynamodb", region_name=REGION)
        resp = client.scan(TableName=TABLE_NAME)
        item = resp["Items"][0]
        assert "ttl" in item
        ttl_val = int(item["ttl"]["N"])
        assert ttl_val > 0

    def test_ttl_approx_6_years_from_event(self, dynamo_sink: DynamoDBSink) -> None:
        event = make_test_event(timestamp="2026-04-15T12:00:00.000Z")
        dynamo_sink.emit(event)

        client = boto3.client("dynamodb", region_name=REGION)
        resp = client.scan(TableName=TABLE_NAME)
        ttl_val = int(resp["Items"][0]["ttl"]["N"])

        from calendar import timegm
        from time import strptime

        event_epoch = timegm(strptime("2026-04-15T12:00:00", "%Y-%m-%dT%H:%M:%S"))
        diff_days = (ttl_val - event_epoch) / 86400
        assert 2189 <= diff_days <= 2191

    def test_ttl_disabled_when_none(self, _aws_env: None) -> None:
        with mock_aws():
            sink = DynamoDBSink(
                table_name=TABLE_NAME,
                region=REGION,
                ttl_days=None,
                create_table=True,
            )
            event = make_test_event()
            sink.emit(event)

            client = boto3.client("dynamodb", region_name=REGION)
            resp = client.scan(TableName=TABLE_NAME)
            item = resp["Items"][0]
            assert "ttl" not in item

    def test_custom_ttl_days(self, _aws_env: None) -> None:
        with mock_aws():
            sink = DynamoDBSink(
                table_name=TABLE_NAME,
                region=REGION,
                ttl_days=365,
                create_table=True,
            )
            event = make_test_event(timestamp="2026-01-01T00:00:00.000Z")
            sink.emit(event)

            client = boto3.client("dynamodb", region_name=REGION)
            resp = client.scan(TableName=TABLE_NAME)
            ttl_val = int(resp["Items"][0]["ttl"]["N"])

            from calendar import timegm
            from time import strptime

            event_epoch = timegm(strptime("2026-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S"))
            diff_days = (ttl_val - event_epoch) / 86400
            assert 364 <= diff_days <= 366

    def test_ttl_disabled_when_zero(self, _aws_env: None) -> None:
        with mock_aws():
            sink = DynamoDBSink(
                table_name=TABLE_NAME,
                region=REGION,
                ttl_days=0,
                create_table=True,
            )
            event = make_test_event()
            sink.emit(event)

            client = boto3.client("dynamodb", region_name=REGION)
            resp = client.scan(TableName=TABLE_NAME)
            item = resp["Items"][0]
            assert "ttl" not in item

    def test_ttl_fallback_on_malformed_timestamp(self, dynamo_sink: DynamoDBSink) -> None:
        event = make_test_event(timestamp="not-a-timestamp")
        dynamo_sink.emit(event)

        client = boto3.client("dynamodb", region_name=REGION)
        resp = client.scan(TableName=TABLE_NAME)
        item = resp["Items"][0]
        assert "ttl" in item
        ttl_val = int(item["ttl"]["N"])
        assert ttl_val > 0


# ------------------------------------------------------------------
# GSI queries
# ------------------------------------------------------------------


def _seed_events(sink: DynamoDBSink) -> list[dict[str, Any]]:
    """Seed the table with a mix of events for query testing."""
    events = [
        make_test_event(
            event_id="aaaaaaaa-0000-0000-0000-000000000001",
            timestamp="2026-04-01T10:00:00.000Z",
            actor={"subject_id": "user_alpha", "subject_type": "human"},
            resource={"type": "Patient", "patient_id": "pat_100", "id": "res_1"},
            action={"type": "READ", "data_classification": "PHI"},
            outcome={"status": "SUCCESS"},
        ),
        make_test_event(
            event_id="aaaaaaaa-0000-0000-0000-000000000002",
            timestamp="2026-04-02T11:00:00.000Z",
            actor={"subject_id": "user_beta", "subject_type": "human"},
            resource={"type": "Patient", "patient_id": "pat_100", "id": "res_2"},
            action={"type": "UPDATE", "data_classification": "PHI"},
            outcome={"status": "SUCCESS"},
        ),
        make_test_event(
            event_id="aaaaaaaa-0000-0000-0000-000000000003",
            timestamp="2026-04-03T12:00:00.000Z",
            actor={"subject_id": "user_alpha", "subject_type": "human"},
            resource={"type": "Encounter", "patient_id": "pat_200", "id": "res_3"},
            action={"type": "READ", "data_classification": "PHI"},
            outcome={"status": "DENIED", "error_type": "AccessDenied"},
        ),
        make_test_event(
            event_id="aaaaaaaa-0000-0000-0000-000000000004",
            timestamp="2026-04-04T09:00:00.000Z",
            actor={"subject_id": "user_alpha", "subject_type": "human"},
            resource={"type": "Patient", "patient_id": "pat_100", "id": "res_4"},
            action={"type": "DELETE", "data_classification": "PHI"},
            outcome={"status": "SUCCESS"},
        ),
    ]
    for e in events:
        sink.emit(e)
    return events


class TestQueryByPatient:
    def test_returns_all_events_for_patient(self, dynamo_sink: DynamoDBSink) -> None:
        _seed_events(dynamo_sink)
        results = dynamo_sink.query_by_patient("pat_100")
        assert len(results) == 3
        event_ids = {r["event_id"] for r in results}
        assert "aaaaaaaa-0000-0000-0000-000000000001" in event_ids
        assert "aaaaaaaa-0000-0000-0000-000000000002" in event_ids
        assert "aaaaaaaa-0000-0000-0000-000000000004" in event_ids

    def test_time_range_filter(self, dynamo_sink: DynamoDBSink) -> None:
        _seed_events(dynamo_sink)
        results = dynamo_sink.query_by_patient(
            "pat_100",
            start="2026-04-02T00:00:00.000Z",
            end="2026-04-03T00:00:00.000Z",
        )
        assert len(results) == 1
        assert results[0]["event_id"] == "aaaaaaaa-0000-0000-0000-000000000002"

    def test_no_results_for_unknown_patient(self, dynamo_sink: DynamoDBSink) -> None:
        _seed_events(dynamo_sink)
        results = dynamo_sink.query_by_patient("pat_nonexistent")
        assert results == []


class TestQueryByActor:
    def test_returns_events_for_actor(self, dynamo_sink: DynamoDBSink) -> None:
        _seed_events(dynamo_sink)
        results = dynamo_sink.query_by_actor("user_alpha")
        assert len(results) == 3

    def test_start_filter(self, dynamo_sink: DynamoDBSink) -> None:
        _seed_events(dynamo_sink)
        results = dynamo_sink.query_by_actor("user_alpha", start="2026-04-03T00:00:00.000Z")
        assert len(results) == 2

    def test_end_filter(self, dynamo_sink: DynamoDBSink) -> None:
        _seed_events(dynamo_sink)
        results = dynamo_sink.query_by_actor("user_alpha", end="2026-04-02T00:00:00.000Z")
        assert len(results) == 1
        assert results[0]["event_id"] == "aaaaaaaa-0000-0000-0000-000000000001"

    def test_start_and_end_filter(self, dynamo_sink: DynamoDBSink) -> None:
        _seed_events(dynamo_sink)
        results = dynamo_sink.query_by_actor(
            "user_alpha",
            start="2026-04-02T00:00:00.000Z",
            end="2026-04-04T00:00:00.000Z",
        )
        assert len(results) == 1
        assert results[0]["event_id"] == "aaaaaaaa-0000-0000-0000-000000000003"


class TestQueryDenials:
    def test_returns_denied_events(self, dynamo_sink: DynamoDBSink) -> None:
        _seed_events(dynamo_sink)
        results = dynamo_sink.query_denials()
        assert len(results) == 1
        assert results[0]["outcome"]["status"] == "DENIED"

    def test_start_filter(self, dynamo_sink: DynamoDBSink) -> None:
        _seed_events(dynamo_sink)
        results = dynamo_sink.query_denials(start="2026-04-04T00:00:00.000Z")
        assert results == []

    def test_end_filter(self, dynamo_sink: DynamoDBSink) -> None:
        _seed_events(dynamo_sink)
        results = dynamo_sink.query_denials(end="2026-04-04T00:00:00.000Z")
        assert len(results) == 1

    def test_start_and_end_no_match(self, dynamo_sink: DynamoDBSink) -> None:
        _seed_events(dynamo_sink)
        results = dynamo_sink.query_denials(
            start="2026-04-04T00:00:00.000Z", end="2026-04-05T00:00:00.000Z"
        )
        assert results == []


# ------------------------------------------------------------------
# Flattened attributes
# ------------------------------------------------------------------


class TestFlattenedAttributes:
    def test_all_expected_attributes_present(self, dynamo_sink: DynamoDBSink) -> None:
        event = _event_with_patient()
        dynamo_sink.emit(event)

        client = boto3.client("dynamodb", region_name=REGION)
        resp = client.scan(TableName=TABLE_NAME)
        item = resp["Items"][0]

        assert "service_date" in item
        assert "ts_event" in item
        assert "event_id" in item
        assert "timestamp" in item
        assert "service_name" in item
        assert "actor_subject_id" in item
        assert "action_type" in item
        assert "resource_type" in item
        assert "outcome_status" in item
        assert "event_json" in item
        assert "patient_id" in item
        assert "resource_id" in item

    def test_optional_fields_omitted_when_absent(self, dynamo_sink: DynamoDBSink) -> None:
        event = make_test_event()
        dynamo_sink.emit(event)

        client = boto3.client("dynamodb", region_name=REGION)
        resp = client.scan(TableName=TABLE_NAME)
        item = resp["Items"][0]
        assert "patient_id" not in item
        assert "resource_id" not in item
        assert "error_type" not in item
        assert "actor_org_id" not in item
        assert "correlation_request_id" not in item
        assert "correlation_session_id" not in item

    def test_correlation_fields_flattened(self, dynamo_sink: DynamoDBSink) -> None:
        event = make_test_event(correlation={"request_id": "req_abc123", "session_id": "sess_xyz"})
        dynamo_sink.emit(event)

        client = boto3.client("dynamodb", region_name=REGION)
        resp = client.scan(TableName=TABLE_NAME)
        item = resp["Items"][0]
        assert item["correlation_request_id"]["S"] == "req_abc123"
        assert item["correlation_session_id"]["S"] == "sess_xyz"

    def test_correlation_partial_fields(self, dynamo_sink: DynamoDBSink) -> None:
        event = make_test_event(correlation={"request_id": "req_only"})
        dynamo_sink.emit(event)

        client = boto3.client("dynamodb", region_name=REGION)
        resp = client.scan(TableName=TABLE_NAME)
        item = resp["Items"][0]
        assert item["correlation_request_id"]["S"] == "req_only"
        assert "correlation_session_id" not in item

    def test_integrity_fields_extracted_when_present(self, dynamo_sink: DynamoDBSink) -> None:
        event = make_test_event(
            integrity={
                "event_hash": "abc123",
                "prev_event_hash": "xyz789",
                "hash_alg": "sha256",
            }
        )
        dynamo_sink.emit(event)

        client = boto3.client("dynamodb", region_name=REGION)
        resp = client.scan(TableName=TABLE_NAME)
        item = resp["Items"][0]
        assert item["chain_hash"]["S"] == "abc123"
        assert item["prev_chain_hash"]["S"] == "xyz789"


# ------------------------------------------------------------------
# Integration with AuditLogger
# ------------------------------------------------------------------


class TestAuditLoggerIntegration:
    def test_audit_logger_emits_to_dynamodb(self, dynamo_sink: DynamoDBSink) -> None:
        config = AuditLoggerConfig(
            service_name="integration-test",
            service_environment="test",
        )
        logger = AuditLogger(config, sink=dynamo_sink)
        logger.audit(
            "READ",
            resource={"type": "Patient", "patient_id": "pat_int"},
        )
        assert logger.stats.events_emitted_total == 1

        client = boto3.client("dynamodb", region_name=REGION)
        resp = client.scan(TableName=TABLE_NAME)
        assert resp["Count"] == 1

    def test_stats_counted_on_emit(self, dynamo_sink: DynamoDBSink) -> None:
        config = AuditLoggerConfig(
            service_name="stats-test",
            service_environment="test",
        )
        logger = AuditLogger(config, sink=dynamo_sink)
        for _ in range(3):
            logger.audit("CREATE", resource={"type": "Note"})
        assert logger.stats.events_emitted_total == 3
        assert logger.stats.emit_failures_total == 0
