"""
Tests for ``_chain.py`` -- canonical serialization and chain hashing.
"""

from __future__ import annotations

import hashlib

import pytest

from bh_audit_logger._chain import canonical_serialize, compute_chain_hash
from tests.conftest import make_test_event


class TestCanonicalSerialize:
    """Tests for canonical_serialize()."""

    def test_excludes_integrity_key(self) -> None:
        event = make_test_event(integrity={"event_hash": "abc", "hash_alg": "sha256"})
        canonical = canonical_serialize(event)
        assert b'"integrity"' not in canonical

    def test_includes_all_other_keys(self) -> None:
        event = make_test_event()
        canonical = canonical_serialize(event)
        assert b'"event_id"' in canonical
        assert b'"service"' in canonical

    def test_deterministic(self) -> None:
        event = make_test_event()
        assert canonical_serialize(event) == canonical_serialize(event)

    def test_sorted_keys(self) -> None:
        event = make_test_event()
        canonical = canonical_serialize(event).decode("utf-8")
        keys_in_order = []
        for key in ["action", "actor", "event_id", "outcome", "resource"]:
            pos = canonical.find(f'"{key}"')
            if pos >= 0:
                keys_in_order.append(pos)
        assert keys_in_order == sorted(keys_in_order)

    def test_compact_separators(self) -> None:
        canonical = canonical_serialize(make_test_event()).decode("utf-8")
        assert ": " not in canonical
        assert ", " not in canonical

    def test_utf8_encoding(self) -> None:
        event = make_test_event()
        event["service"]["name"] = "café-service"
        canonical = canonical_serialize(event)
        assert isinstance(canonical, bytes)
        assert "café-service".encode() in canonical

    def test_different_events_different_bytes(self) -> None:
        e1 = make_test_event(event_id="aaa")
        e2 = make_test_event(event_id="bbb")
        assert canonical_serialize(e1) != canonical_serialize(e2)


class TestComputeChainHash:
    """Tests for compute_chain_hash()."""

    def test_returns_integrity_dict(self) -> None:
        result = compute_chain_hash(make_test_event())
        assert "event_hash" in result
        assert "hash_alg" in result
        assert result["hash_alg"] == "sha256"

    def test_first_event_no_prev_hash(self) -> None:
        result = compute_chain_hash(make_test_event())
        assert "prev_event_hash" not in result

    def test_with_prev_hash(self) -> None:
        result = compute_chain_hash(make_test_event(), prev_hash="deadbeef")
        assert result["prev_event_hash"] == "deadbeef"

    def test_deterministic(self) -> None:
        event = make_test_event()
        r1 = compute_chain_hash(event, prev_hash="abc")
        r2 = compute_chain_hash(event, prev_hash="abc")
        assert r1["event_hash"] == r2["event_hash"]

    def test_different_events_different_hashes(self) -> None:
        e1 = make_test_event(event_id="aaa")
        e2 = make_test_event(event_id="bbb")
        h1 = compute_chain_hash(e1)["event_hash"]
        h2 = compute_chain_hash(e2)["event_hash"]
        assert h1 != h2

    def test_prev_hash_affects_result(self) -> None:
        event = make_test_event()
        h1 = compute_chain_hash(event, prev_hash=None)["event_hash"]
        h2 = compute_chain_hash(event, prev_hash="abc")["event_hash"]
        assert h1 != h2

    def test_sha256_produces_64_char_hex(self) -> None:
        result = compute_chain_hash(make_test_event(), algorithm="sha256")
        assert len(result["event_hash"]) == 64

    def test_sha384_produces_96_char_hex(self) -> None:
        result = compute_chain_hash(make_test_event(), algorithm="sha384")
        assert len(result["event_hash"]) == 96
        assert result["hash_alg"] == "sha384"

    def test_sha512_produces_128_char_hex(self) -> None:
        result = compute_chain_hash(make_test_event(), algorithm="sha512")
        assert len(result["event_hash"]) == 128
        assert result["hash_alg"] == "sha512"

    def test_hash_matches_manual_computation(self) -> None:
        event = make_test_event()
        prev = "prev_abc"
        canonical = canonical_serialize(event)
        h = hashlib.sha256()
        h.update(prev.encode("utf-8"))
        h.update(canonical)
        expected = h.hexdigest()
        result = compute_chain_hash(event, prev_hash=prev)
        assert result["event_hash"] == expected

    def test_unsupported_algorithm_raises(self) -> None:
        with pytest.raises(ValueError, match="Unsupported hash algorithm"):
            compute_chain_hash(make_test_event(), algorithm="md5")

    def test_integrity_excluded_from_hash(self) -> None:
        """Adding integrity to event doesn't change the hash."""
        event = make_test_event()
        h1 = compute_chain_hash(event)["event_hash"]
        event_with_integrity = {
            **event,
            "integrity": {"event_hash": "old", "hash_alg": "sha256"},
        }
        h2 = compute_chain_hash(event_with_integrity)["event_hash"]
        assert h1 == h2
