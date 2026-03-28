"""
Vendored bh-audit-schema v1.1 for offline validation.

The JSON schema is included in this package to enable validation
without network access.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1.1"
SCHEMA_PATH = Path(__file__).parent / "audit_event.schema.json"


def get_schema_path() -> Path:
    """Return the path to the vendored audit event schema."""
    return SCHEMA_PATH


@lru_cache(maxsize=1)
def load_schema() -> dict[str, Any]:
    """Load and return the audit event schema as a dictionary.

    The result is cached to avoid repeated disk reads.

    Raises:
        FileNotFoundError: With an actionable message if the schema file
            is missing (e.g. corrupt install).
    """
    try:
        with open(SCHEMA_PATH) as f:
            return json.load(f)
    except FileNotFoundError:
        raise FileNotFoundError(
            f"Vendored audit schema not found at {SCHEMA_PATH}. "
            f"Reinstall the package: pip install --force-reinstall bh-audit-logger"
        ) from None
