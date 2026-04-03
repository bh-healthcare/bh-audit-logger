"""
Tests for ``_chain_state.py`` -- in-memory and DynamoDB chain state.
"""

from __future__ import annotations

import threading
from collections.abc import Generator

import pytest

from bh_audit_logger._chain_state import ChainState


class TestChainState:
    """Tests for the in-memory ChainState."""

    def test_initial_last_hash_is_none(self) -> None:
        state = ChainState()
        assert state.last_hash is None

    def test_initial_hash_from_constructor(self) -> None:
        state = ChainState(initial_hash="seed_hash")
        assert state.last_hash == "seed_hash"

    def test_first_advance_returns_none(self) -> None:
        state = ChainState()
        prev = state.advance("hash_1")
        assert prev is None

    def test_advance_returns_previous(self) -> None:
        state = ChainState()
        state.advance("hash_1")
        prev = state.advance("hash_2")
        assert prev == "hash_1"

    def test_advance_chain(self) -> None:
        state = ChainState()
        state.advance("a")
        state.advance("b")
        prev = state.advance("c")
        assert prev == "b"
        assert state.last_hash == "c"

    def test_last_hash_updates(self) -> None:
        state = ChainState()
        state.advance("x")
        assert state.last_hash == "x"
        state.advance("y")
        assert state.last_hash == "y"

    def test_thread_safety(self) -> None:
        """Concurrent advances don't lose hashes."""
        state = ChainState()
        results: list[str | None] = []
        lock = threading.Lock()

        def worker(hash_val: str) -> None:
            prev = state.advance(hash_val)
            with lock:
                results.append(prev)

        threads = [threading.Thread(target=worker, args=(f"h{i}",)) for i in range(100)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(results) == 100
        none_count = sum(1 for r in results if r is None)
        assert none_count == 1
        assert state.last_hash is not None

    def test_has_slots(self) -> None:
        state = ChainState()
        assert hasattr(state, "__slots__")
        with pytest.raises(AttributeError):
            state.unexpected_attr = "boom"  # type: ignore[attr-defined]


class TestDynamoDBChainState:
    """Tests for DynamoDBChainState (using moto)."""

    @pytest.fixture(autouse=True)
    def _aws_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
        monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
        monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
        monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")

    @pytest.fixture
    def chain_state(self) -> Generator:
        moto = pytest.importorskip("moto")
        from bh_audit_logger._chain_state import DynamoDBChainState

        with moto.mock_aws():
            cs = DynamoDBChainState(
                table_name="bh_audit_chain_state",
                service_name="test-svc",
                region="us-east-1",
                create_table=True,
            )
            yield cs

    def test_first_advance_returns_none(self, chain_state: ChainState) -> None:
        from bh_audit_logger._chain_state import DynamoDBChainState

        assert isinstance(chain_state, DynamoDBChainState)
        prev = chain_state.advance("hash_1")
        assert prev is None

    def test_second_advance_returns_previous(self, chain_state: ChainState) -> None:
        chain_state.advance("hash_1")
        prev = chain_state.advance("hash_2")
        assert prev == "hash_1"

    def test_different_services_independent(self) -> None:
        """Separate DynamoDBChainState instances with different service_names are independent."""
        moto = pytest.importorskip("moto")
        from bh_audit_logger._chain_state import DynamoDBChainState

        with moto.mock_aws():
            cs_a = DynamoDBChainState(
                table_name="bh_audit_chain_state",
                service_name="svc-a",
                region="us-east-1",
                create_table=True,
            )
            cs_b = DynamoDBChainState(
                table_name="bh_audit_chain_state",
                service_name="svc-b",
                region="us-east-1",
            )
            cs_a.advance("hash_a1")
            cs_b.advance("hash_b1")
            prev_a = cs_a.advance("hash_a2")
            prev_b = cs_b.advance("hash_b2")
            assert prev_a == "hash_a1"
            assert prev_b == "hash_b1"

    def test_table_name_property(self, chain_state: ChainState) -> None:
        from bh_audit_logger._chain_state import DynamoDBChainState

        assert isinstance(chain_state, DynamoDBChainState)
        assert chain_state.table_name == "bh_audit_chain_state"

    def test_service_name_property(self, chain_state: ChainState) -> None:
        from bh_audit_logger._chain_state import DynamoDBChainState

        assert isinstance(chain_state, DynamoDBChainState)
        assert chain_state.service_name == "test-svc"

    def test_last_hash_property(self, chain_state: ChainState) -> None:
        assert chain_state.last_hash is None
        chain_state.advance("hash_1")
        assert chain_state.last_hash == "hash_1"
        chain_state.advance("hash_2")
        assert chain_state.last_hash == "hash_2"

    def test_create_table_idempotent(self) -> None:
        moto = pytest.importorskip("moto")
        from bh_audit_logger._chain_state import DynamoDBChainState

        with moto.mock_aws():
            DynamoDBChainState(
                table_name="bh_audit_chain_state",
                service_name="svc",
                region="us-east-1",
                create_table=True,
            )
            cs2 = DynamoDBChainState(
                table_name="bh_audit_chain_state",
                service_name="svc",
                region="us-east-1",
                create_table=True,
            )
            prev = cs2.advance("h1")
            assert prev is None
