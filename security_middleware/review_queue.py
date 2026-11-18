"""Local storage for content that requires a human review decision."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field

from security_middleware.content_protection import (ContentEnvelope, ContentInspectionResult,
    OriginTrust, DataSensitivity)


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
    origin_trust: OriginTrust = OriginTrust.UNTRUSTED
    data_sensitivity: DataSensitivity = DataSensitivity.CONFIDENTIAL


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
        # Existing rows lack reliable labels: migrate conservatively without
        # rewriting their text or decisions. New inserts supply explicit labels.
        columns = {row[1] for row in connection.execute('PRAGMA table_info(content_reviews)')}
        if 'origin_trust' not in columns:
            connection.execute("ALTER TABLE content_reviews ADD COLUMN origin_trust TEXT NOT NULL DEFAULT 'untrusted'")
        if 'data_sensitivity' not in columns:
            connection.execute("ALTER TABLE content_reviews ADD COLUMN data_sensitivity TEXT NOT NULL DEFAULT 'confidential'")


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
                    (source_id, content_id, content, reason, status, created_at, origin_trust, data_sensitivity)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    envelope.source_id,
                    envelope.content_id,
                    envelope.content,
                    inspection.reason,
                    "PENDING",
                    created_at,
                    envelope.origin_trust.value,
                    envelope.data_sensitivity.value,
                ),
            )
        return ReviewItem(
            review_id=cursor.lastrowid,
            source_id=envelope.source_id,
            content_id=envelope.content_id,
            content=envelope.content,
            reason=inspection.reason,
            status="PENDING",
            origin_trust=envelope.origin_trust,
            data_sensitivity=envelope.data_sensitivity,
        )

    def pending(self) -> list[ReviewItem]:
        """Return currently unresolved review items for the local dashboard."""
        with sqlite3.connect(self._database_path) as connection:
            rows = connection.execute(
                """
                SELECT review_id, source_id, content_id, content, reason, status,
                       reviewed_excerpt, origin_trust, data_sensitivity
                FROM content_reviews
                WHERE status = 'PENDING'
                ORDER BY review_id DESC
                """
            ).fetchall()
        return [
            ReviewItem(
                review_id=row[0],
                source_id=row[1],
                content_id=row[2],
                content=row[3],
                reason=row[4],
                status=row[5],
                reviewed_excerpt=row[6],
                origin_trust=row[7], data_sensitivity=row[8],
            )
            for row in rows
        ]

    def decide(
        self,
        review_id: int,
        decision: ReviewDecision,
        reviewed_excerpt: str | None = None,
    ) -> ReviewItem:
        """Record rejection or a specific excerpt approved for content use."""
        if decision is ReviewDecision.APPROVED and (not reviewed_excerpt or not reviewed_excerpt.strip()):
            raise ValueError("An approved review requires a reviewed excerpt.")

        reviewed_at = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self._database_path) as connection:
            if decision is ReviewDecision.APPROVED:
                original = connection.execute(
                    'SELECT content FROM content_reviews WHERE review_id = ? AND status = ?',
                    (review_id, 'PENDING'),
                ).fetchone()
                if original is None or reviewed_excerpt not in original[0]:
                    raise ValueError('Approved excerpt must occur in the held original content.')
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
                       reviewed_excerpt, origin_trust, data_sensitivity
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
            origin_trust=row[7], data_sensitivity=row[8],
        )

    def approved_content(self, review_id: int) -> ContentEnvelope:
        """Release only a decided excerpt; approval never upgrades origin trust.

        This is a local reviewer API, not authentication or tool authorization.
        Caller must intentionally request this release. No automatic model retry.
        """
        with sqlite3.connect(self._database_path) as connection:
            row = connection.execute(
                'SELECT source_id, content_id, content, status, reviewed_excerpt, data_sensitivity '
                'FROM content_reviews WHERE review_id = ?', (review_id,),
            ).fetchone()
        if (row is None or row[3] != 'APPROVED' or not row[4]
                or not row[4].strip() or row[4] not in row[2]):
            raise ValueError('No valid approved excerpt is available for release.')
        return ContentEnvelope(source_id=row[0], content_id=row[1],
            origin_trust=OriginTrust.UNTRUSTED, data_sensitivity=row[5], content=row[4])
