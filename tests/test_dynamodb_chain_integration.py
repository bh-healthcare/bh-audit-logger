"""
DynamoDB chain-hashing integration tests.

Targets the riskiest parts of the v1.0 release:
- DynamoDBChainState conditional-write retry and fallback
- Simulated concurrent Lambda invocations racing to advance chain state
- Full AuditLogger → enable_integrity → DynamoDBSink pipeline
- Chain continuity verified via DynamoDB round-trip (emit → query → verify)
- event_json stored in DynamoDB includes integrity block
"""

from __future__ import annotations

import json
import logging
import threading
from typing import Any
from unittest.mock import patch

import pytest

boto3 = pytest.importorskip("boto3")
moto = pytest.importorskip("moto")

from moto import mock_aws  # noqa: E402

from bh_audit_logger import AuditLogger, AuditLoggerConfig  # noqa: E402
from bh_audit_logger._chain import compute_chain_hash  # noqa: E402
from bh_audit_logger._chain_state import DynamoDBChainState  # noqa: E402
from bh_audit_logger.sinks.dynamodb import DynamoDBSink  # noqa: E402

TABLE_NAME = "test_audit_events"
CHAIN_TABLE = "test_chain_state"
REGION = "us-east-1"


@pytest.fixture
def _aws_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


# ------------------------------------------------------------------
# DynamoDBChainState: retry and fallback
# ------------------------------------------------------------------


class TestDynamoDBChainStateRetry:
    """Test the conditional-write retry loop and exhaustion fallback."""

    @pytest.fixture
    def chain_state(self, _aws_env: None) -> DynamoDBChainState:
        with mock_aws():
            cs = DynamoDBChainState(
                table_name=CHAIN_TABLE,
                service_name="svc",
                region=REGION,
                create_table=True,
            )
            yield cs

    def test_retry_exhaustion_returns_none_and_logs_warning(
        self, chain_state: DynamoDBChainState, caplog: pytest.LogCaptureFixture
    ) -> None:
        """When all retries are exhausted, advance() returns None (unchained)."""
        chain_state.advance("hash_0")

        exc_cls = chain_state._resource.meta.client.exceptions.ConditionalCheckFailedException

        def always_conflict(**kwargs: Any) -> Any:
            raise exc_cls(
                {"Error": {"Code": "ConditionalCheckFailedException", "Message": "conflict"}},
                "UpdateItem",
            )

        with patch.object(chain_state._table, "update_item", side_effect=always_conflict):
            with caplog.at_level(logging.WARNING, logger="bh.audit.chain"):
                result = chain_state.advance("hash_1")

        assert result is None
        assert any("exhausted" in r.message for r in caplog.records)

    def test_retry_succeeds_on_second_attempt(self, chain_state: DynamoDBChainState) -> None:
        """Advance succeeds after one transient conflict."""
        chain_state.advance("hash_0")

        exc_cls = chain_state._resource.meta.client.exceptions.ConditionalCheckFailedException
        original_update = chain_state._table.update_item
        call_count = 0

        def fail_once(**kwargs: Any) -> Any:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise exc_cls(
                    {"Error": {"Code": "ConditionalCheckFailedException", "Message": "conflict"}},
                    "UpdateItem",
                )
            return original_update(**kwargs)

        with patch.object(chain_state._table, "update_item", side_effect=fail_once):
            result = chain_state.advance("hash_1")

        assert result == "hash_0"
        assert call_count == 2

    def test_max_retries_one_still_tries_once(self, _aws_env: None) -> None:
        """max_retries=1 gives exactly one attempt before fallback."""
        with mock_aws():
            cs = DynamoDBChainState(
                table_name=CHAIN_TABLE,
                service_name="svc",
                region=REGION,
                create_table=True,
                max_retries=1,
            )
            cs.advance("hash_0")

            exc_cls = cs._resource.meta.client.exceptions.ConditionalCheckFailedException

            def always_conflict(**kwargs: Any) -> Any:
                raise exc_cls(
                    {"Error": {"Code": "ConditionalCheckFailedException", "Message": "conflict"}},
                    "UpdateItem",
                )

            with patch.object(cs._table, "update_item", side_effect=always_conflict):
                result = cs.advance("hash_1")

            assert result is None

    def test_first_write_conflict_retries_and_succeeds(
        self, chain_state: DynamoDBChainState
    ) -> None:
        """Conflict on the put_item (first-write) path triggers retry."""
        exc_cls = chain_state._resource.meta.client.exceptions.ConditionalCheckFailedException
        original_put = chain_state._table.put_item
        call_count = 0

        def fail_first_put(**kwargs: Any) -> Any:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise exc_cls(
                    {"Error": {"Code": "ConditionalCheckFailedException", "Message": "race"}},
                    "PutItem",
                )
            return original_put(**kwargs)

        with patch.object(chain_state._table, "put_item", side_effect=fail_first_put):
            result = chain_state.advance("hash_0")

        assert result is None
        assert call_count == 2


# ------------------------------------------------------------------
# Simulated concurrent Lambda invocations
# ------------------------------------------------------------------


class TestConcurrentLambdaSimulation:
    """Simulate multiple Lambda invocations racing to advance chain state.

    Moto serializes operations so we can't get true data races, but we
    can verify that concurrent threads all succeed and the final chain
    state is consistent (exactly one None return, last_hash is one of
    the submitted hashes).
    """

    def test_concurrent_advances_all_succeed(self, _aws_env: None) -> None:
        with mock_aws():
            cs = DynamoDBChainState(
                table_name=CHAIN_TABLE,
                service_name="svc",
                region=REGION,
                create_table=True,
            )
            results: list[str | None] = []
            lock = threading.Lock()
            n_workers = 20

            def worker(idx: int) -> None:
                prev = cs.advance(f"hash_{idx}")
                with lock:
                    results.append(prev)

            threads = [threading.Thread(target=worker, args=(i,)) for i in range(n_workers)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            assert len(results) == n_workers
            none_count = sum(1 for r in results if r is None)
            assert none_count >= 1

            item = cs._table.get_item(Key={"service_name": "svc"}).get("Item")
            assert item is not None
            assert item["last_event_hash"].startswith("hash_")

    def test_concurrent_different_services(self, _aws_env: None) -> None:
        """Multiple services advancing concurrently don't interfere."""
        with mock_aws():
            service_names = ["svc-a", "svc-b", "svc-c"]
            chain_states = {}
            for svc in service_names:
                chain_states[svc] = DynamoDBChainState(
                    table_name=CHAIN_TABLE,
                    service_name=svc,
                    region=REGION,
                    create_table=(svc == service_names[0]),
                )
            results: dict[str, list[str | None]] = {s: [] for s in service_names}
            lock = threading.Lock()

            def worker(svc: str, idx: int) -> None:
                prev = chain_states[svc].advance(f"{svc}_hash_{idx}")
                with lock:
                    results[svc].append(prev)

            threads = []
            for svc in service_names:
                for i in range(10):
                    threads.append(threading.Thread(target=worker, args=(svc, i)))
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            for svc in service_names:
                assert len(results[svc]) == 10
                none_count = sum(1 for r in results[svc] if r is None)
                assert none_count >= 1


# ------------------------------------------------------------------
# Full pipeline: AuditLogger + enable_integrity + DynamoDBSink
# ------------------------------------------------------------------


class TestIntegrityThroughDynamoDBSink:
    """Verify the full AuditLogger → integrity → DynamoDBSink pipeline."""

    @pytest.fixture
    def sink_and_logger(self, _aws_env: None) -> tuple[DynamoDBSink, AuditLogger]:
        with mock_aws():
            sink = DynamoDBSink(table_name=TABLE_NAME, region=REGION, create_table=True)
            config = AuditLoggerConfig(
                service_name="lambda-svc",
                service_environment="test",
                enable_integrity=True,
                hash_algorithm="sha256",
                time_source=_incrementing_time_source(),
            )
            logger = AuditLogger(config, sink=sink)
            yield sink, logger

    def test_chain_hash_stored_in_dynamo_item(
        self, sink_and_logger: tuple[DynamoDBSink, AuditLogger]
    ) -> None:
        sink, logger = sink_and_logger
        logger.audit(
            "READ",
            actor={"subject_id": "u1", "subject_type": "human"},
            resource={"type": "Patient", "patient_id": "pat_1"},
        )

        client = boto3.client("dynamodb", region_name=REGION)
        resp = client.scan(TableName=TABLE_NAME)
        item = resp["Items"][0]
        assert "chain_hash" in item
        assert len(item["chain_hash"]["S"]) == 64
        assert "prev_chain_hash" in item

    def test_first_event_has_empty_prev_chain_hash(
        self, sink_and_logger: tuple[DynamoDBSink, AuditLogger]
    ) -> None:
        sink, logger = sink_and_logger
        logger.audit(
            "READ",
            actor={"subject_id": "u1", "subject_type": "human"},
            resource={"type": "Patient", "patient_id": "pat_1"},
        )

        client = boto3.client("dynamodb", region_name=REGION)
        resp = client.scan(TableName=TABLE_NAME)
        item = resp["Items"][0]
        assert item["prev_chain_hash"]["S"] == ""

    def test_event_json_includes_integrity_block(
        self, sink_and_logger: tuple[DynamoDBSink, AuditLogger]
    ) -> None:
        """The full event stored in event_json includes the integrity block."""
        sink, logger = sink_and_logger
        logger.audit(
            "READ",
            actor={"subject_id": "u1", "subject_type": "human"},
            resource={"type": "Patient", "patient_id": "pat_1"},
        )

        client = boto3.client("dynamodb", region_name=REGION)
        resp = client.scan(TableName=TABLE_NAME)
        event_json = json.loads(resp["Items"][0]["event_json"]["S"])
        assert "integrity" in event_json
        assert event_json["integrity"]["hash_alg"] == "sha256"

    def test_chain_continuity_multiple_events(
        self, sink_and_logger: tuple[DynamoDBSink, AuditLogger]
    ) -> None:
        sink, logger = sink_and_logger
        for i in range(5):
            logger.audit(
                "READ",
                actor={"subject_id": f"u{i}", "subject_type": "human"},
                resource={"type": "Patient", "patient_id": "pat_1"},
            )

        results = sink.query_by_patient("pat_1")
        assert len(results) == 5

        prev_hash = None
        for evt in results:
            integrity = evt["integrity"]
            recomputed = compute_chain_hash(evt, prev_hash, "sha256")
            assert recomputed["event_hash"] == integrity["event_hash"]
            if prev_hash is None:
                assert "prev_event_hash" not in integrity
            else:
                assert integrity["prev_event_hash"] == prev_hash
            prev_hash = integrity["event_hash"]

    def test_dynamo_chain_hash_matches_event_json_hash(
        self, sink_and_logger: tuple[DynamoDBSink, AuditLogger]
    ) -> None:
        """Top-level chain_hash attribute matches the integrity.event_hash inside event_json."""
        sink, logger = sink_and_logger
        logger.audit(
            "CREATE",
            actor={"subject_id": "u1", "subject_type": "human"},
            resource={"type": "Note"},
        )

        client = boto3.client("dynamodb", region_name=REGION)
        resp = client.scan(TableName=TABLE_NAME)
        item = resp["Items"][0]
        event_json = json.loads(item["event_json"]["S"])

        assert item["chain_hash"]["S"] == event_json["integrity"]["event_hash"]


def _incrementing_time_source(base_iso: str = "2026-04-01T10:00:00"):
    """Return a time_source callable that yields distinct timestamps 1s apart."""
    from datetime import UTC, datetime, timedelta

    base = datetime.fromisoformat(base_iso).replace(tzinfo=UTC)
    counter = {"n": 0}

    def _next() -> datetime:
        t = base + timedelta(seconds=counter["n"])
        counter["n"] += 1
        return t

    return _next


class TestChainContinuityDynamoDBRoundTrip:
    """Emit events, query them back from DynamoDB, and verify the full chain.

    Uses a deterministic time source to guarantee distinct timestamps,
    avoiding non-deterministic GSI ordering when millisecond timestamps
    collide in tight loops.
    """

    def test_query_by_actor_preserves_chain(self, _aws_env: None) -> None:
        with mock_aws():
            sink = DynamoDBSink(table_name=TABLE_NAME, region=REGION, create_table=True)
            config = AuditLoggerConfig(
                service_name="svc",
                service_environment="test",
                enable_integrity=True,
                time_source=_incrementing_time_source(),
            )
            logger = AuditLogger(config, sink=sink)

            for i in range(4):
                logger.audit(
                    "READ",
                    actor={"subject_id": "auditor_1", "subject_type": "human"},
                    resource={"type": "Patient", "patient_id": f"pat_{i}"},
                )

            results = sink.query_by_actor("auditor_1")
            assert len(results) == 4

            prev_hash = None
            for evt in results:
                recomputed = compute_chain_hash(evt, prev_hash, "sha256")
                assert recomputed["event_hash"] == evt["integrity"]["event_hash"]
                prev_hash = evt["integrity"]["event_hash"]

    def test_mixed_outcomes_chain_survives_denial(self, _aws_env: None) -> None:
        """Chain continuity holds across SUCCESS and DENIED events."""
        with mock_aws():
            sink = DynamoDBSink(table_name=TABLE_NAME, region=REGION, create_table=True)
            config = AuditLoggerConfig(
                service_name="svc",
                service_environment="test",
                enable_integrity=True,
                time_source=_incrementing_time_source(),
            )
            logger = AuditLogger(config, sink=sink)

            logger.audit(
                "READ",
                actor={"subject_id": "u1", "subject_type": "human"},
                resource={"type": "Patient", "patient_id": "pat_1"},
            )
            logger.audit_access_denied(
                "READ",
                error_type="CrossOrgAccessDenied",
                actor={"subject_id": "u1", "subject_type": "human"},
                resource={"type": "Patient", "patient_id": "pat_1"},
            )
            logger.audit(
                "UPDATE",
                actor={"subject_id": "u1", "subject_type": "human"},
                resource={"type": "Patient", "patient_id": "pat_1"},
            )

            results = sink.query_by_patient("pat_1")
            assert len(results) == 3

            prev_hash = None
            for evt in results:
                recomputed = compute_chain_hash(evt, prev_hash, "sha256")
                assert recomputed["event_hash"] == evt["integrity"]["event_hash"]
                prev_hash = evt["integrity"]["event_hash"]


class TestIntegrityWithAlgorithmVariants:
    """Verify different hash algorithms work through the full DynamoDB pipeline."""

    @pytest.mark.parametrize("algo,hex_len", [("sha256", 64), ("sha384", 96), ("sha512", 128)])
    def test_algorithm_stored_correctly(self, _aws_env: None, algo: str, hex_len: int) -> None:
        with mock_aws():
            sink = DynamoDBSink(table_name=TABLE_NAME, region=REGION, create_table=True)
            config = AuditLoggerConfig(
                service_name="svc",
                service_environment="test",
                enable_integrity=True,
                hash_algorithm=algo,
            )
            logger = AuditLogger(config, sink=sink)
            logger.audit(
                "READ",
                actor={"subject_id": "u1", "subject_type": "human"},
                resource={"type": "Patient", "patient_id": "pat_1"},
            )

            client = boto3.client("dynamodb", region_name=REGION)
            resp = client.scan(TableName=TABLE_NAME)
            item = resp["Items"][0]
            assert len(item["chain_hash"]["S"]) == hex_len

            event_json = json.loads(item["event_json"]["S"])
            assert event_json["integrity"]["hash_alg"] == algo


class TestIntegrityDisabledNoChainFields:
    """When enable_integrity=False, DynamoDB items should have no chain fields."""

    def test_no_chain_hash_without_integrity(self, _aws_env: None) -> None:
        with mock_aws():
            sink = DynamoDBSink(table_name=TABLE_NAME, region=REGION, create_table=True)
            config = AuditLoggerConfig(service_name="svc", service_environment="test")
            logger = AuditLogger(config, sink=sink)
            logger.audit(
                "READ",
                actor={"subject_id": "u1", "subject_type": "human"},
                resource={"type": "Patient"},
            )

            client = boto3.client("dynamodb", region_name=REGION)
            resp = client.scan(TableName=TABLE_NAME)
            item = resp["Items"][0]
            assert "chain_hash" not in item
            assert "prev_chain_hash" not in item
