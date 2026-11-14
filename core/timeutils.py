"""
INDRA INFINITY SECURITY ∞ — TIME UTILITIES
Single source of naive-UTC timestamps (SQLite stores naive datetimes).
Replaces the deprecated datetime.utcnow().
"""

from datetime import datetime, timezone


def utcnow() -> datetime:
    """Returns the current UTC time as a naive datetime (DB-compatible)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)
