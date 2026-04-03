"""
Ledger sink: JSONL file sink with built-in chain hashing.

Combines ``JsonlFileSink`` and ``ChainState`` into a single sink that
writes tamper-evident audit events to a local JSONL file.  Each event
gets an ``integrity`` block injected before it's written to disk.

Use this sink for local development, testing, or single-process
deployments where you want chain hashing without configuring
``enable_integrity`` on the ``AuditLogger``.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from bh_audit_logger._chain import compute_chain_hash
from bh_audit_logger._chain_state import ChainState
from bh_audit_logger.sinks.jsonl import JsonlFileSink

_log = logging.getLogger("bh.audit.chain")


class LedgerSink:
    """JSONL file sink with built-in chain hashing.

    Wraps ``JsonlFileSink`` and an internal ``ChainState`` so every
    event written to disk includes an ``integrity`` block with
    ``event_hash``, ``prev_event_hash``, and ``hash_alg``.

    Args:
        path: Path to the output JSONL file.
        flush: Flush after each write (default *True*).
        algorithm: Hash algorithm (``"sha256"``, ``"sha384"``, ``"sha512"``).
    """

    def __init__(
        self,
        path: str | Path,
        *,
        flush: bool = True,
        algorithm: str = "sha256",
    ) -> None:
        self._jsonl = JsonlFileSink(path, flush=flush)
        self._chain = ChainState()
        self._algorithm = algorithm

    def emit(self, event: dict[str, Any]) -> None:
        """Inject integrity block and write the event to the JSONL file."""
        if "integrity" in event:
            _log.warning(
                "LedgerSink: event already has integrity block "
                "(possible double-hashing); overwriting with "
                "LedgerSink's own chain hash"
            )
        integrity = compute_chain_hash(event, self._chain.last_hash, self._algorithm)
        event = {**event, "integrity": integrity}
        self._chain.advance(integrity["event_hash"])
        self._jsonl.emit(event)

    def close(self) -> None:
        """Close the underlying JSONL file."""
        self._jsonl.close()

    @property
    def path(self) -> Path:
        """Return the path to the output file."""
        return self._jsonl.path

    @property
    def chain_state(self) -> ChainState:
        """Return the internal chain state (for inspection/testing)."""
        return self._chain

    def __enter__(self) -> LedgerSink:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        self.close()
