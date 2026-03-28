"""
Typed event block definitions conforming to bh-audit-schema v1.1.

Uses the required-base / optional-extension pattern so type checkers
enforce required fields (e.g. ServiceBlock must have ``name``).
"""

from __future__ import annotations

from typing import Literal, NotRequired, TypedDict

ActionType = Literal[
    "READ",
    "CREATE",
    "UPDATE",
    "DELETE",
    "EXPORT",
    "LOGIN",
    "LOGOUT",
    "PRINT",
    "OTHER",
]
OutcomeStatus = Literal["SUCCESS", "FAILURE", "DENIED"]
ActorType = Literal["human", "service"]
DataClassification = Literal["PHI", "PII", "NONE", "UNKNOWN"]
EmitFailureMode = Literal["silent", "log", "raise"]
HashAlgorithm = Literal["sha256", "sha384", "sha512"]


class _ServiceRequired(TypedDict):
    name: str


class ServiceBlock(_ServiceRequired, total=False):
    environment: str
    version: str


class CorrelationBlock(TypedDict, total=False):
    request_id: str
    trace_id: str
    session_id: str


class _ActorRequired(TypedDict):
    subject_id: str
    subject_type: ActorType


class ActorBlock(_ActorRequired, total=False):
    org_id: str
    owner_org_id: str
    roles: list[str]


class _ActionRequired(TypedDict):
    type: ActionType


class ActionBlock(_ActionRequired, total=False):
    name: str
    phi_touched: bool
    data_classification: DataClassification


class _ResourceRequired(TypedDict):
    type: str


class ResourceBlock(_ResourceRequired, total=False):
    id: str
    patient_id: str


class _OutcomeRequired(TypedDict):
    status: OutcomeStatus


class OutcomeBlock(_OutcomeRequired, total=False):
    error_type: str
    error_message: str


class IntegrityBlock(TypedDict, total=False):
    event_hash: str
    prev_event_hash: str
    hash_alg: HashAlgorithm


class AuditEvent(TypedDict):
    """Audit event with required top-level keys enforced."""

    schema_version: str
    event_id: str
    timestamp: str
    service: ServiceBlock
    actor: ActorBlock
    action: ActionBlock
    resource: ResourceBlock
    outcome: OutcomeBlock
    correlation: NotRequired[CorrelationBlock]
    integrity: NotRequired[IntegrityBlock]
    metadata: NotRequired[dict[str, str | int | float | bool | None]]
