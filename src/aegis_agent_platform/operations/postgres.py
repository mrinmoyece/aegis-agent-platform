"""PostgreSQL probes for production operation gates."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

import psycopg


class SchemaCursor(Protocol):
    """Minimal asynchronous cursor required by the schema probe."""

    async def fetchone(self) -> Sequence[object] | None:
        """Return one aggregate migration-history row."""
        ...


class SchemaConnection(Protocol):
    """Minimal PostgreSQL connection required by the schema probe."""

    async def execute(self, query: str) -> SchemaCursor:
        """Execute a schema-history query."""
        ...


class PostgresSchemaVersionProbe:
    """Read and validate the contiguous database migration history."""

    def __init__(self, connection: SchemaConnection) -> None:
        self._connection = connection

    async def __call__(self) -> int | None:
        """Return the current schema version or unavailable for invalid history."""
        try:
            cursor = await self._connection.execute(
                """
                SELECT count(*), min(version), max(version)
                FROM aegis_schema_migrations
                """
            )
            row = await cursor.fetchone()
        except psycopg.Error:
            return None
        if (
            row is None
            or len(row) != 3
            or not all(
                isinstance(value, int) and not isinstance(value, bool) for value in row
            )
        ):
            return None
        count, minimum, maximum = row
        assert isinstance(count, int)
        assert isinstance(minimum, int)
        assert isinstance(maximum, int)
        if minimum != 1 or count != maximum:
            return None
        return maximum
