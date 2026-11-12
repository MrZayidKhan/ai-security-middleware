"""Small local audit store for UI-visible security events."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel


class AuditEvent(BaseModel):
    event_id: int
    created_at: str
    event_type: str
    task_id: str | None
    decision: str | None
    reason: str
    details: dict[str, object]


def initialize_audit_database(database_path: Path) -> None:
    """Create the local event table used by the dashboard."""
    database_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS security_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                event_type TEXT NOT NULL,
                task_id TEXT,
                decision TEXT,
                reason TEXT NOT NULL,
                details_json TEXT NOT NULL
            )
            """
        )


class AuditLog:
    """Store concise security events without writing full document contents."""

    def __init__(self, database_path: Path) -> None:
        self._database_path = database_path

    def record(
        self,
        event_type: str,
        reason: str,
        details: dict[str, object],
        task_id: str | None = None,
        decision: str | None = None,
    ) -> AuditEvent:
        """Persist one event and return the stored record."""
        created_at = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self._database_path) as connection:
            cursor = connection.execute(
                """
                INSERT INTO security_events
                    (created_at, event_type, task_id, decision, reason, details_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    created_at,
                    event_type,
                    task_id,
                    decision,
                    reason,
                    json.dumps(details, sort_keys=True),
                ),
            )
        return AuditEvent(
            event_id=cursor.lastrowid,
            created_at=created_at,
            event_type=event_type,
            task_id=task_id,
            decision=decision,
            reason=reason,
            details=details,
        )

    def recent(self, limit: int = 50) -> list[AuditEvent]:
        """Return recent events, newest first."""
        with sqlite3.connect(self._database_path) as connection:
            rows = connection.execute(
                """
                SELECT event_id, created_at, event_type, task_id, decision, reason,
                       details_json
                FROM security_events
                ORDER BY event_id DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            AuditEvent(
                event_id=row[0],
                created_at=row[1],
                event_type=row[2],
                task_id=row[3],
                decision=row[4],
                reason=row[5],
                details=json.loads(row[6]),
            )
            for row in rows
        ]
