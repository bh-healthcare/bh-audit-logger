"""
Chain state management for tamper-evident audit trails.

Provides two implementations:

- ``ChainState``: thread-safe, in-memory (single-process).
- ``DynamoDBChainState``: multi-process safe via conditional writes
  (requires ``boto3``).
"""

from __future__ import annotations

import logging
import threading
from typing import Any

_log = logging.getLogger("bh.audit.chain")


class ChainState:
    """Thread-safe, in-memory chain state for single-process deployments.

    Tracks the most recent event hash so it can be fed as
    ``prev_event_hash`` into the next event's integrity block.

    Args:
        initial_hash: Seed hash for resuming a chain (e.g. from a
                      previous process run).  *None* starts a new chain.
    """

    __slots__ = ("_lock", "_last_hash")

    def __init__(self, initial_hash: str | None = None) -> None:
        self._lock = threading.Lock()
        self._last_hash = initial_hash

    def advance(self, event_hash: str) -> str | None:
        """Record a new event hash and return the previous one.

        Returns *None* for the first event in a chain.
        """
        with self._lock:
            prev = self._last_hash
            self._last_hash = event_hash
            return prev

    @property
    def last_hash(self) -> str | None:
        """The most recent event hash, or *None* if no events yet."""
        with self._lock:
            return self._last_hash


class DynamoDBChainState:
    """DynamoDB-backed chain state for multi-process / Lambda deployments.

    Uses a dedicated ``bh_audit_chain_state`` table with conditional writes
    to prevent lost updates when multiple processes emit concurrently.

    The API is intentionally compatible with ``ChainState``: both expose
    ``advance(event_hash) -> str | None`` and a ``last_hash`` property,
    so callers can swap implementations without code changes.

    Args:
        table_name: DynamoDB table name (default ``"bh_audit_chain_state"``).
        service_name: Partition key identifying the chain
                      (default ``"default"``).
        region: AWS region.  *None* uses the boto3 default chain.
        create_table: Create the table if it doesn't exist (dev/test only).
        endpoint_url: Override the DynamoDB endpoint (for DynamoDB Local).
        max_retries: Max retries on conditional-write conflicts before
                     falling back to unchained emission.
    """

    def __init__(
        self,
        table_name: str = "bh_audit_chain_state",
        service_name: str = "default",
        region: str | None = None,
        create_table: bool = False,
        endpoint_url: str | None = None,
        max_retries: int = 3,
    ) -> None:
        try:
            import boto3
        except ImportError as exc:
            raise ImportError(
                "DynamoDBChainState requires boto3. "
                "Install with: pip install bh-audit-logger[dynamodb]"
            ) from exc

        self._table_name = table_name
        self._service_name = service_name
        self._max_retries = max_retries

        kwargs: dict[str, Any] = {"service_name": "dynamodb"}
        if region is not None:
            kwargs["region_name"] = region
        if endpoint_url is not None:
            kwargs["endpoint_url"] = endpoint_url
        self._resource = boto3.resource(**kwargs)
        self._table = self._resource.Table(table_name)

        if create_table:
            self._create_table()

    def _create_table(self) -> None:
        """Create the chain state table.  Idempotent."""
        try:
            self._resource.create_table(
                TableName=self._table_name,
                KeySchema=[
                    {"AttributeName": "service_name", "KeyType": "HASH"},
                ],
                AttributeDefinitions=[
                    {"AttributeName": "service_name", "AttributeType": "S"},
                ],
                BillingMode="PAY_PER_REQUEST",
            )
            self._table.wait_until_exists()
        except self._resource.meta.client.exceptions.ResourceInUseException:
            pass

    def advance(self, event_hash: str) -> str | None:
        """Atomically update chain state and return the previous hash.

        Uses conditional writes to prevent lost updates.  Retries up to
        ``max_retries`` times on conflict, then returns *None* (unchained)
        to avoid blocking the emit path.
        """
        service_name = self._service_name
        for _attempt in range(self._max_retries):
            item = self._table.get_item(
                Key={"service_name": service_name},
            ).get("Item")

            if item is None:
                try:
                    self._table.put_item(
                        Item={
                            "service_name": service_name,
                            "last_event_hash": event_hash,
                        },
                        ConditionExpression="attribute_not_exists(service_name)",
                    )
                    return None
                except self._resource.meta.client.exceptions.ConditionalCheckFailedException:
                    continue
            else:
                prev_hash = item.get("last_event_hash")
                try:
                    self._table.update_item(
                        Key={"service_name": service_name},
                        UpdateExpression="SET last_event_hash = :new_hash",
                        ConditionExpression="last_event_hash = :expected",
                        ExpressionAttributeValues={
                            ":new_hash": event_hash,
                            ":expected": prev_hash,
                        },
                    )
                    return prev_hash
                except self._resource.meta.client.exceptions.ConditionalCheckFailedException:
                    continue

        _log.warning(
            "DynamoDBChainState: exhausted %d retries for service=%s; "
            "falling back to unchained emission",
            self._max_retries,
            service_name,
        )
        return None

    @property
    def last_hash(self) -> str | None:
        """Read the current chain head from DynamoDB."""
        resp = self._table.get_item(
            Key={"service_name": self._service_name},
        )
        item = resp.get("Item")
        if item is None:
            return None
        return item.get("last_event_hash")

    @property
    def table_name(self) -> str:
        """Return the DynamoDB table name."""
        return self._table_name

    @property
    def service_name(self) -> str:
        """Return the service name (partition key)."""
        return self._service_name
