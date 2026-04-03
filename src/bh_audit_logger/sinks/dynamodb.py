"""
DynamoDB sink for audit events.

Writes events to a single-table DynamoDB design optimized for healthcare
compliance query patterns.  Requires ``boto3``:

    pip install bh-audit-logger[dynamodb]

Table uses a composite primary key (service_date / ts_event) with three
Global Secondary Indexes for patient-access, actor-activity, and
outcome-status queries.
"""

from __future__ import annotations

import json
import logging
from calendar import timegm
from datetime import UTC, datetime
from typing import Any

_log = logging.getLogger("bh.audit.internal")

_PROVISION = {
    "ReadCapacityUnits": 5,
    "WriteCapacityUnits": 5,
}


class DynamoDBSink:
    """Audit sink that writes events to DynamoDB.

    Designed for production healthcare deployments.  Events are flattened
    into top-level DynamoDB attributes for efficient GSI queries and stored
    with their full JSON representation in ``event_json``.

    Args:
        table_name: DynamoDB table name (default ``"bh_audit_events"``).
        region: AWS region.  When *None*, uses boto3 default chain.
        ttl_days: Days until TTL expiration (default 2190 ≈ 6 years).
                  Set to *None* to disable TTL.
        create_table: If *True*, create table + GSIs on first use
                      (dev/test only -- never enable in production).
    """

    def __init__(
        self,
        table_name: str = "bh_audit_events",
        region: str | None = None,
        ttl_days: int | None = 2190,
        create_table: bool = False,
    ) -> None:
        try:
            import boto3
        except ImportError as exc:
            raise ImportError(
                "DynamoDBSink requires boto3. Install with: pip install bh-audit-logger[dynamodb]"
            ) from exc

        self._table_name = table_name
        self._ttl_days = ttl_days

        kwargs: dict[str, Any] = {"service_name": "dynamodb"}
        if region is not None:
            kwargs["region_name"] = region
        self._resource = boto3.resource(**kwargs)
        self._table = self._resource.Table(table_name)

        if create_table:
            self._create_table()

    # ------------------------------------------------------------------
    # Table creation (dev / test only)
    # ------------------------------------------------------------------

    def _create_table(self) -> None:
        """Create the audit events table with three GSIs.

        Idempotent: silently succeeds if the table already exists.
        """
        try:
            self._resource.create_table(
                TableName=self._table_name,
                KeySchema=[
                    {"AttributeName": "service_date", "KeyType": "HASH"},
                    {"AttributeName": "ts_event", "KeyType": "RANGE"},
                ],
                AttributeDefinitions=[
                    {"AttributeName": "service_date", "AttributeType": "S"},
                    {"AttributeName": "ts_event", "AttributeType": "S"},
                    {"AttributeName": "patient_id", "AttributeType": "S"},
                    {"AttributeName": "actor_subject_id", "AttributeType": "S"},
                    {"AttributeName": "outcome_status", "AttributeType": "S"},
                    {"AttributeName": "timestamp", "AttributeType": "S"},
                ],
                GlobalSecondaryIndexes=[
                    {
                        "IndexName": "patient_id-index",
                        "KeySchema": [
                            {"AttributeName": "patient_id", "KeyType": "HASH"},
                            {"AttributeName": "timestamp", "KeyType": "RANGE"},
                        ],
                        "Projection": {
                            "ProjectionType": "INCLUDE",
                            "NonKeyAttributes": [
                                "event_id",
                                "action_type",
                                "actor_subject_id",
                                "outcome_status",
                                "data_classification",
                                "http_route_template",
                                "event_json",
                            ],
                        },
                        "ProvisionedThroughput": _PROVISION,
                    },
                    {
                        "IndexName": "actor-index",
                        "KeySchema": [
                            {"AttributeName": "actor_subject_id", "KeyType": "HASH"},
                            {"AttributeName": "timestamp", "KeyType": "RANGE"},
                        ],
                        "Projection": {
                            "ProjectionType": "INCLUDE",
                            "NonKeyAttributes": [
                                "event_id",
                                "action_type",
                                "resource_type",
                                "patient_id",
                                "outcome_status",
                                "http_route_template",
                                "event_json",
                            ],
                        },
                        "ProvisionedThroughput": _PROVISION,
                    },
                    {
                        "IndexName": "outcome-index",
                        "KeySchema": [
                            {"AttributeName": "outcome_status", "KeyType": "HASH"},
                            {"AttributeName": "timestamp", "KeyType": "RANGE"},
                        ],
                        "Projection": {
                            "ProjectionType": "INCLUDE",
                            "NonKeyAttributes": [
                                "event_id",
                                "actor_subject_id",
                                "action_type",
                                "resource_type",
                                "patient_id",
                                "error_type",
                                "event_json",
                            ],
                        },
                        "ProvisionedThroughput": _PROVISION,
                    },
                ],
                ProvisionedThroughput=_PROVISION,
            )
            self._table.wait_until_exists()
        except self._resource.meta.client.exceptions.ResourceInUseException:
            pass

    # ------------------------------------------------------------------
    # Emit
    # ------------------------------------------------------------------

    def emit(self, event: dict[str, Any]) -> None:
        """Write an audit event to DynamoDB.

        Flattens key fields into top-level attributes for GSI queries,
        stores full event JSON in ``event_json``, and sets TTL if
        configured.  Uses a condition expression on ``event_id`` to
        prevent duplicate writes.

        Raises on DynamoDB errors so the caller's failure-isolation
        policy (``emit_failure_mode``) can decide what to do.
        """
        item = self._flatten_for_dynamo(event)

        try:
            self._table.put_item(
                Item=item,
                ConditionExpression="attribute_not_exists(event_id)",
            )
        except self._resource.meta.client.exceptions.ConditionalCheckFailedException:
            _log.debug(
                "Duplicate audit event skipped: event_id=%s",
                event.get("event_id"),
            )

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def query_by_patient(
        self,
        patient_id: str,
        start: str | None = None,
        end: str | None = None,
    ) -> list[dict[str, Any]]:
        """Query GSI1 for patient access history.

        Returns parsed audit events ordered by timestamp.
        """
        from boto3.dynamodb.conditions import Key

        condition = Key("patient_id").eq(patient_id)
        if start and end:
            condition = condition & Key("timestamp").between(start, end)
        elif start:
            condition = condition & Key("timestamp").gte(start)
        elif end:
            condition = condition & Key("timestamp").lte(end)

        resp = self._table.query(
            IndexName="patient_id-index",
            KeyConditionExpression=condition,
        )
        return self._parse_items(resp.get("Items", []))

    def query_by_actor(
        self,
        actor_id: str,
        start: str | None = None,
    ) -> list[dict[str, Any]]:
        """Query GSI2 for user activity audit.

        Returns parsed audit events ordered by timestamp.
        """
        from boto3.dynamodb.conditions import Key

        condition = Key("actor_subject_id").eq(actor_id)
        if start:
            condition = condition & Key("timestamp").gte(start)

        resp = self._table.query(
            IndexName="actor-index",
            KeyConditionExpression=condition,
        )
        return self._parse_items(resp.get("Items", []))

    def query_denials(
        self,
        start: str | None = None,
    ) -> list[dict[str, Any]]:
        """Query GSI3 for all DENIED outcomes.

        Returns parsed audit events ordered by timestamp.
        """
        from boto3.dynamodb.conditions import Key

        condition = Key("outcome_status").eq("DENIED")
        if start:
            condition = condition & Key("timestamp").gte(start)

        resp = self._table.query(
            IndexName="outcome-index",
            KeyConditionExpression=condition,
        )
        return self._parse_items(resp.get("Items", []))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _flatten_for_dynamo(self, event: dict[str, Any]) -> dict[str, Any]:
        """Extract top-level attributes from nested event for GSI queries."""
        service = event.get("service", {})
        actor = event.get("actor", {})
        action = event.get("action", {})
        resource = event.get("resource", {})
        outcome = event.get("outcome", {})

        ts = event.get("timestamp", "")
        service_name = service.get("name", "unknown")

        item: dict[str, Any] = {
            "service_date": f"{service_name}#{ts[:10]}",
            "ts_event": f"{ts}#{event.get('event_id', '')}",
            "event_id": event.get("event_id", ""),
            "timestamp": ts,
            "service_name": service_name,
            "environment": service.get("environment", ""),
            "actor_subject_id": actor.get("subject_id", ""),
            "actor_subject_type": actor.get("subject_type", ""),
            "action_type": action.get("type", ""),
            "action_phi_touched": action.get("phi_touched", False),
            "data_classification": action.get("data_classification", "UNKNOWN"),
            "resource_type": resource.get("type", ""),
            "outcome_status": outcome.get("status", ""),
            "event_json": json.dumps(event, separators=(",", ":"), ensure_ascii=False),
        }

        if actor.get("org_id"):
            item["actor_org_id"] = actor["org_id"]
        if actor.get("owner_org_id"):
            item["actor_owner_org_id"] = actor["owner_org_id"]
        if resource.get("id"):
            item["resource_id"] = resource["id"]
        if resource.get("patient_id"):
            item["patient_id"] = resource["patient_id"]
        if outcome.get("error_type"):
            item["error_type"] = outcome["error_type"]

        integrity = event.get("integrity", {})
        if integrity:
            item["chain_hash"] = integrity.get("event_hash", "")
            item["prev_chain_hash"] = integrity.get("prev_event_hash", "")

        if self._ttl_days is not None:
            item["ttl"] = self._compute_ttl(ts)

        return item

    def _compute_ttl(self, iso_timestamp: str) -> int:
        """Compute Unix epoch TTL from an ISO 8601 timestamp string."""
        try:
            ts_str = iso_timestamp.replace("Z", "+00:00")
            dt = datetime.fromisoformat(ts_str)
        except (ValueError, AttributeError):
            dt = datetime.now(UTC)
        epoch = timegm(dt.utctimetuple())
        return epoch + (self._ttl_days or 0) * 86400

    @staticmethod
    def _parse_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Parse ``event_json`` from DynamoDB items back into dicts."""
        results: list[dict[str, Any]] = []
        for item in items:
            raw = item.get("event_json")
            if raw:
                results.append(json.loads(raw))
            else:
                results.append(item)
        return results

    @property
    def table_name(self) -> str:
        """Return the DynamoDB table name."""
        return self._table_name
