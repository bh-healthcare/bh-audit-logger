"""
Shared fixtures for bh-audit-logger tests.
"""

import json
from pathlib import Path

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
