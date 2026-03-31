"""
Vendored bh-audit-schema for offline validation.

Supports loading schema by version (1.0, 1.1). The JSON schemas are
included in this package to enable validation without network access.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1.1"

_VERSIONS_DIR = Path(__file__).parent / "versions"


def get_schema_path(version: str = "1.1") -> Path:
    """Return the path to the vendored audit event schema for *version*."""
    return _VERSIONS_DIR / version / "audit_event.schema.json"


@lru_cache(maxsize=4)
def load_schema(version: str = "1.1") -> dict[str, Any]:
    """Load and return the audit event schema for *version* as a dictionary.

    The result is cached per version to avoid repeated disk reads.

    Raises:
        FileNotFoundError: With an actionable message if the schema file
            is missing (e.g. corrupt install or unsupported version).
    """
    path = get_schema_path(version)
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        raise FileNotFoundError(
            f"Vendored audit schema v{version} not found at {path}. "
            f"Available versions: {sorted(p.name for p in _VERSIONS_DIR.iterdir() if p.is_dir())}. "
            f"Reinstall the package: pip install --force-reinstall bh-audit-logger"
        ) from None
