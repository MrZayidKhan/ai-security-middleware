"""Local storage for content that requires a human review decision."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field

from security_middleware.content_protection import ContentEnvelope, ContentInspectionResult


class ReviewDecision(str, Enum):
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class ReviewItem(BaseModel):
    review_id: int
    source_id: str
    content_id: str
    content: str
    reason: str
    status: str
    reviewed_excerpt: str | None = None


def initialize_review_database(database_path: Path) -> None:
    """Create the local pending-review table."""
    database_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS content_reviews (
                review_id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id TEXT NOT NULL,
                content_id TEXT NOT NULL,
                content TEXT NOT NULL,
                reason TEXT NOT NULL,
                status TEXT NOT NULL,
                reviewed_excerpt TEXT,
                created_at TEXT NOT NULL,
                reviewed_at TEXT
            )
            """
        )


class ReviewQueue:
    """Store and decide held content without changing action permissions."""

    def __init__(self, database_path: Path) -> None:
        self._database_path = database_path

    def create(
        self, envelope: ContentEnvelope, inspection: ContentInspectionResult
    ) -> ReviewItem:
        """Store held content for review and return its identifier."""
        created_at = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self._database_path) as connection:
            cursor = connection.execute(
                """
                INSERT INTO content_reviews
                    (source_id, content_id, content, reason, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    envelope.source_id,
                    envelope.content_id,
                    envelope.content,
                    inspection.reason,
                    "PENDING",
                    created_at,
                ),
            )
        return ReviewItem(
            review_id=cursor.lastrowid,
            source_id=envelope.source_id,
            content_id=envelope.content_id,
            content=envelope.content,
            reason=inspection.reason,
            status="PENDING",
        )

    def decide(
        self,
        review_id: int,
        decision: ReviewDecision,
        reviewed_excerpt: str | None = None,
    ) -> ReviewItem:
        """Record rejection or a specific excerpt approved for content use."""
        if decision is ReviewDecision.APPROVED and not reviewed_excerpt:
            raise ValueError("An approved review requires a reviewed excerpt.")

        reviewed_at = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self._database_path) as connection:
            cursor = connection.execute(
                """
                UPDATE content_reviews
                SET status = ?, reviewed_excerpt = ?, reviewed_at = ?
                WHERE review_id = ? AND status = 'PENDING'
                """,
                (decision.value, reviewed_excerpt, reviewed_at, review_id),
            )
            if cursor.rowcount != 1:
                raise ValueError("Review item is missing or already decided.")
            row = connection.execute(
                """
                SELECT review_id, source_id, content_id, content, reason, status,
                       reviewed_excerpt
                FROM content_reviews WHERE review_id = ?
                """,
                (review_id,),
            ).fetchone()

        return ReviewItem(
            review_id=row[0],
            source_id=row[1],
            content_id=row[2],
            content=row[3],
            reason=row[4],
            status=row[5],
            reviewed_excerpt=row[6],
        )
