"""
Integration tests for chain hashing through AuditLogger.
"""

from __future__ import annotations

from bh_audit_logger import (
    AuditLogger,
    AuditLoggerConfig,
    ChainState,
    MemorySink,
)
from bh_audit_logger._chain import compute_chain_hash


class TestIntegrityDisabledByDefault:
    """Verify integrity is off when not explicitly enabled."""

    def test_no_integrity_block(self) -> None:
        sink = MemorySink()
        logger = AuditLogger(AuditLoggerConfig(service_name="svc"), sink=sink)
        logger.audit("READ", resource={"type": "Patient"})
        assert "integrity" not in sink.events[0]

    def test_chain_state_is_none(self) -> None:
        logger = AuditLogger(AuditLoggerConfig(service_name="svc"))
        assert logger.chain_state is None


class TestIntegrityEnabled:
    """Verify chain hashing when enable_integrity=True."""

    def test_events_have_integrity_block(self) -> None:
        sink = MemorySink()
        logger = AuditLogger(
            AuditLoggerConfig(service_name="svc", enable_integrity=True),
            sink=sink,
        )
        logger.audit("READ", resource={"type": "Patient"})
        event = sink.events[0]
        assert "integrity" in event
        assert "event_hash" in event["integrity"]
        assert event["integrity"]["hash_alg"] == "sha256"

    def test_first_event_no_prev_hash(self) -> None:
        sink = MemorySink()
        logger = AuditLogger(
            AuditLoggerConfig(service_name="svc", enable_integrity=True),
            sink=sink,
        )
        logger.audit("READ", resource={"type": "Patient"})
        assert "prev_event_hash" not in sink.events[0]["integrity"]

    def test_chain_continuity(self) -> None:
        sink = MemorySink()
        logger = AuditLogger(
            AuditLoggerConfig(service_name="svc", enable_integrity=True),
            sink=sink,
        )
        for _ in range(5):
            logger.audit("READ", resource={"type": "Patient"})

        events = sink.events
        for i in range(1, len(events)):
            assert (
                events[i]["integrity"]["prev_event_hash"]
                == events[i - 1]["integrity"]["event_hash"]
            )

    def test_hashes_verify_correctly(self) -> None:
        sink = MemorySink()
        logger = AuditLogger(
            AuditLoggerConfig(service_name="svc", enable_integrity=True),
            sink=sink,
        )
        for _ in range(3):
            logger.audit("READ", resource={"type": "Patient"})

        prev_hash = None
        for event in sink.events:
            recomputed = compute_chain_hash(event, prev_hash, "sha256")
            assert recomputed["event_hash"] == event["integrity"]["event_hash"]
            prev_hash = event["integrity"]["event_hash"]

    def test_auto_creates_chain_state(self) -> None:
        logger = AuditLogger(
            AuditLoggerConfig(service_name="svc", enable_integrity=True),
        )
        assert logger.chain_state is not None
        assert isinstance(logger.chain_state, ChainState)

    def test_custom_chain_state(self) -> None:
        cs = ChainState(initial_hash="seed")
        sink = MemorySink()
        logger = AuditLogger(
            AuditLoggerConfig(service_name="svc", enable_integrity=True),
            sink=sink,
            chain_state=cs,
        )
        assert logger.chain_state is cs
        logger.audit("READ", resource={"type": "Patient"})
        assert sink.events[0]["integrity"]["prev_event_hash"] == "seed"

    def test_custom_algorithm(self) -> None:
        sink = MemorySink()
        logger = AuditLogger(
            AuditLoggerConfig(
                service_name="svc",
                enable_integrity=True,
                hash_algorithm="sha512",
            ),
            sink=sink,
        )
        logger.audit("READ", resource={"type": "Patient"})
        event = sink.events[0]
        assert event["integrity"]["hash_alg"] == "sha512"
        assert len(event["integrity"]["event_hash"]) == 128

    def test_stats_still_counted(self) -> None:
        sink = MemorySink()
        logger = AuditLogger(
            AuditLoggerConfig(service_name="svc", enable_integrity=True),
            sink=sink,
        )
        logger.audit("READ", resource={"type": "Patient"})
        assert logger.stats.events_emitted_total == 1

    def test_integrity_events_total_counter(self) -> None:
        sink = MemorySink()
        logger = AuditLogger(
            AuditLoggerConfig(service_name="svc", enable_integrity=True),
            sink=sink,
        )
        for _ in range(3):
            logger.audit("READ", resource={"type": "Patient"})
        assert logger.stats.integrity_events_total == 3
        assert logger.stats.chain_gaps_total == 0

    def test_chain_gaps_counter_on_failure(self) -> None:
        """If chain hashing fails, event still emits but chain_gaps_total increments."""
        sink = MemorySink()
        cs = ChainState()
        logger = AuditLogger(
            AuditLoggerConfig(service_name="svc", enable_integrity=True),
            sink=sink,
            chain_state=cs,
        )
        # Sabotage chain state to trigger an exception during hashing
        cs._last_hash = object()  # type: ignore[assignment]
        logger.audit("READ", resource={"type": "Patient"})
        assert logger.stats.chain_gaps_total == 1
        assert logger.stats.events_emitted_total == 1
        assert "integrity" not in sink.events[0]

    def test_emit_method_also_gets_integrity(self) -> None:
        """Direct emit() path also injects integrity."""
        sink = MemorySink()
        logger = AuditLogger(
            AuditLoggerConfig(service_name="svc", enable_integrity=True),
            sink=sink,
        )
        event = {
            "schema_version": "1.1",
            "event_id": "12345678-1234-5678-1234-567812345678",
            "timestamp": "2026-04-01T00:00:00.000Z",
            "service": {"name": "svc", "environment": "test"},
            "actor": {"subject_id": "user1", "subject_type": "human"},
            "action": {"type": "READ", "data_classification": "UNKNOWN"},
            "resource": {"type": "Patient"},
            "outcome": {"status": "SUCCESS"},
        }
        logger.emit(event)
        assert "integrity" in sink.events[0]
