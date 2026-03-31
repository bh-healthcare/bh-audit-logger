"""
Shared fixtures for bh-audit-logger tests.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from bh_audit_logger import AuditLoggerConfig, MemorySink


@pytest.fixture
def phi_tokens() -> list[str]:
    """Load synthetic PHI tokens from fixture file."""
    fixture_path = Path(__file__).parent / "fixtures" / "phi_tokens.json"
    with open(fixture_path) as f:
        data = json.load(f)
    return data["tokens"]


@pytest.fixture
def memory_sink() -> MemorySink:
    """Create a fresh memory sink for testing."""
    return MemorySink()


@pytest.fixture
def test_config() -> AuditLoggerConfig:
    """Create standard test audit config."""
    return AuditLoggerConfig(
        service_name="test-service",
        service_environment="test",
    )


def make_test_event(**overrides: Any) -> dict[str, Any]:
    """Return a minimal valid v1.1 event dict, with optional overrides."""
    event: dict[str, Any] = {
        "schema_version": "1.1",
        "event_id": "12345678-1234-5678-1234-567812345678",
        "timestamp": "2026-03-30T12:00:00.000Z",
        "service": {"name": "test-service", "environment": "test"},
        "actor": {"subject_id": "test-user", "subject_type": "human"},
        "action": {"type": "READ", "data_classification": "UNKNOWN"},
        "resource": {"type": "TestResource"},
        "outcome": {"status": "SUCCESS"},
    }
    event.update(overrides)
    return event
