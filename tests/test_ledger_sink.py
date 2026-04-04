"""
Tests for ``sinks/ledger.py`` -- LedgerSink (JSONL + chain hashing).
"""

from __future__ import annotations

import json
from pathlib import Path

from bh_audit_logger._chain import compute_chain_hash
from bh_audit_logger.sinks.ledger import LedgerSink
from tests.conftest import make_test_event


class TestLedgerSink:
    """Tests for LedgerSink."""

    def test_emit_writes_to_file(self, tmp_path: Path) -> None:
        path = tmp_path / "audit.jsonl"
        with LedgerSink(path) as sink:
            sink.emit(make_test_event())
        lines = path.read_text().strip().splitlines()
        assert len(lines) == 1

    def test_event_has_integrity_block(self, tmp_path: Path) -> None:
        path = tmp_path / "audit.jsonl"
        with LedgerSink(path) as sink:
            sink.emit(make_test_event())
        event = json.loads(path.read_text().strip())
        assert "integrity" in event
        assert "event_hash" in event["integrity"]
        assert "hash_alg" in event["integrity"]
        assert event["integrity"]["hash_alg"] == "sha256"

    def test_first_event_no_prev_hash(self, tmp_path: Path) -> None:
        path = tmp_path / "audit.jsonl"
        with LedgerSink(path) as sink:
            sink.emit(make_test_event())
        event = json.loads(path.read_text().strip())
        assert "prev_event_hash" not in event["integrity"]

    def test_chain_continuity(self, tmp_path: Path) -> None:
        """Each event's prev_event_hash matches the previous event's event_hash."""
        path = tmp_path / "audit.jsonl"
        with LedgerSink(path) as sink:
            for i in range(5):
                sink.emit(make_test_event(event_id=f"evt_{i}"))
        lines = path.read_text().strip().splitlines()
        events = [json.loads(line) for line in lines]

        assert "prev_event_hash" not in events[0]["integrity"]
        for i in range(1, len(events)):
            assert (
                events[i]["integrity"]["prev_event_hash"]
                == events[i - 1]["integrity"]["event_hash"]
            )

    def test_roundtrip_hash_verification(self, tmp_path: Path) -> None:
        """Read back events and verify each hash independently."""
        path = tmp_path / "audit.jsonl"
        with LedgerSink(path) as sink:
            for i in range(3):
                sink.emit(make_test_event(event_id=f"evt_{i}"))

        lines = path.read_text().strip().splitlines()
        events = [json.loads(line) for line in lines]

        prev_hash = None
        for event in events:
            integrity = event["integrity"]
            recomputed = compute_chain_hash(event, prev_hash, integrity["hash_alg"])
            assert recomputed["event_hash"] == integrity["event_hash"]
            prev_hash = integrity["event_hash"]

    def test_custom_algorithm(self, tmp_path: Path) -> None:
        path = tmp_path / "audit.jsonl"
        with LedgerSink(path, algorithm="sha512") as sink:
            sink.emit(make_test_event())
        event = json.loads(path.read_text().strip())
        assert event["integrity"]["hash_alg"] == "sha512"
        assert len(event["integrity"]["event_hash"]) == 128

    def test_context_manager_closes_file(self, tmp_path: Path) -> None:
        path = tmp_path / "audit.jsonl"
        sink = LedgerSink(path)
        sink.__enter__()
        sink.emit(make_test_event())
        sink.__exit__(None, None, None)
        assert path.exists()

    def test_chain_state_property(self, tmp_path: Path) -> None:
        sink = LedgerSink(tmp_path / "audit.jsonl")
        assert sink.chain_state is not None
        assert sink.chain_state.last_hash is None
        sink.emit(make_test_event())
        assert sink.chain_state.last_hash is not None

    def test_path_property(self, tmp_path: Path) -> None:
        p = tmp_path / "audit.jsonl"
        sink = LedgerSink(p)
        assert sink.path == p

    def test_tamper_detection(self, tmp_path: Path) -> None:
        """Modifying an event in the file breaks the chain."""
        path = tmp_path / "audit.jsonl"
        with LedgerSink(path) as sink:
            for i in range(3):
                sink.emit(make_test_event(event_id=f"evt_{i}"))

        lines = path.read_text().strip().splitlines()
        events = [json.loads(line) for line in lines]
        events[1]["action"]["type"] = "DELETE"

        prev_hash = events[0]["integrity"]["event_hash"]
        tampered = events[1]
        recomputed = compute_chain_hash(tampered, prev_hash, tampered["integrity"]["hash_alg"])
        assert recomputed["event_hash"] != tampered["integrity"]["event_hash"]
