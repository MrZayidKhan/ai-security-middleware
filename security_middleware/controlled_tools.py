"""Narrow local tools used by later security-gateway milestones."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import TypeVar

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator


DOCUMENT_FILES = {
    "project-overview": "project_overview.txt",
    "security-scope": "security_scope.txt",
    "untrusted-injection": "untrusted_injection.txt",
    "sanitizable-instruction": "sanitizable_instruction.txt",
}
APPROVED_RECIPIENTS = {"project-team@example.test", "supervisor@example.test"}


class ToolInputError(ValueError):
    """Raised when a tool receives invalid or out-of-scope input."""


class ToolExecutionError(RuntimeError):
    """Raised when an approved local resource cannot be used safely."""


class ToolArguments(BaseModel):
    """Base arguments model that rejects fields outside a tool contract."""

    model_config = ConfigDict(extra="forbid")


class SearchDocumentsRequest(ToolArguments):
    query: str = Field(min_length=1, max_length=200)

    @field_validator("query")
    @classmethod
    def reject_blank_query(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("query cannot be blank")
        return value


class ReadDocumentRequest(ToolArguments):
    document_id: str = Field(min_length=1, max_length=64)


class ProjectRecordRequest(ToolArguments):
    record_id: int = Field(ge=1, le=999)


class DraftMessageRequest(ToolArguments):
    recipient: str = Field(min_length=3, max_length=100)
    subject: str = Field(min_length=1, max_length=120)
    body: str = Field(min_length=1, max_length=2_000)

    @field_validator("recipient", "subject", "body")
    @classmethod
    def strip_required_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("value cannot be blank")
        return value


class DocumentMatch(BaseModel):
    document_id: str
    title: str


class DocumentContent(BaseModel):
    document_id: str
    content: str


class ProjectRecord(BaseModel):
    record_id: int
    title: str
    status: str
    category: str


class OutboxDraft(BaseModel):
    draft_id: int
    recipient: str
    subject: str
    body: str
    status: str
    created_at: str


ModelType = TypeVar("ModelType", bound=BaseModel)


def initialize_demo_databases(database_path: Path, outbox_path: Path) -> None:
    """Create the fixed synthetic records and simulated-outbox schema."""
    database_path.parent.mkdir(parents=True, exist_ok=True)
    outbox_path.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS project_records (
                record_id INTEGER PRIMARY KEY,
                title TEXT NOT NULL,
                status TEXT NOT NULL,
                category TEXT NOT NULL
            )
            """
        )
        connection.executemany(
            """
            INSERT OR IGNORE INTO project_records (record_id, title, status, category)
            VALUES (?, ?, ?, ?)
            """,
            [
                (1, "Middleware design", "active", "planning"),
                (2, "Tool interface", "pending", "development"),
            ],
        )

    with sqlite3.connect(outbox_path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS outbox_drafts (
                draft_id INTEGER PRIMARY KEY AUTOINCREMENT,
                recipient TEXT NOT NULL,
                subject TEXT NOT NULL,
                body TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )


class ControlledTools:
    """Perform only approved document, database, and outbox operations."""

    def __init__(
        self, document_root: Path, database_path: Path, outbox_path: Path
    ) -> None:
        self._document_root = document_root.resolve()
        self._database_path = database_path
        self._outbox_path = outbox_path

    def search_documents(self, query: str) -> list[DocumentMatch]:
        """Search the small approved document set by fixed document ID."""
        request = self._validate(SearchDocumentsRequest, {"query": query})
        matches: list[DocumentMatch] = []

        for document_id in DOCUMENT_FILES:
            content = self.read_document(document_id).content
            if request.query.casefold() in content.casefold():
                title = content.splitlines()[0]
                matches.append(DocumentMatch(document_id=document_id, title=title))

        return matches

    def read_document(self, document_id: str) -> DocumentContent:
        """Read one document chosen by an approved identifier, never a raw path."""
        request = self._validate(ReadDocumentRequest, {"document_id": document_id})
        document_path = self._approved_document_path(request.document_id)

        try:
            content = document_path.read_text(encoding="utf-8")
        except OSError as error:
            raise ToolExecutionError("Could not read the approved document.") from error

        return DocumentContent(document_id=request.document_id, content=content)

    def get_project_record(self, record_id: int) -> ProjectRecord | None:
        """Read one synthetic record through a fixed parameterized SQL query."""
        request = self._validate(ProjectRecordRequest, {"record_id": record_id})

        try:
            with sqlite3.connect(self._database_path) as connection:
                connection.row_factory = sqlite3.Row
                row = connection.execute(
                    """
                    SELECT record_id, title, status, category
                    FROM project_records
                    WHERE record_id = ?
                    """,
                    (request.record_id,),
                ).fetchone()
        except sqlite3.Error as error:
            raise ToolExecutionError("Could not query the project records.") from error

        return ProjectRecord.model_validate(dict(row)) if row else None

    def draft_message(self, recipient: str, subject: str, body: str) -> OutboxDraft:
        """Store an approved synthetic draft without sending any message."""
        request = self._validate(
            DraftMessageRequest,
            {"recipient": recipient, "subject": subject, "body": body},
        )
        if request.recipient not in APPROVED_RECIPIENTS:
            raise ToolInputError("recipient is not approved for the simulated outbox")

        created_at = datetime.now(timezone.utc).isoformat()
        try:
            with sqlite3.connect(self._outbox_path) as connection:
                cursor = connection.execute(
                    """
                    INSERT INTO outbox_drafts (recipient, subject, body, status, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        request.recipient,
                        request.subject,
                        request.body,
                        "DRAFT",
                        created_at,
                    ),
                )
        except sqlite3.Error as error:
            raise ToolExecutionError("Could not store the simulated message draft.") from error

        return OutboxDraft(
            draft_id=cursor.lastrowid,
            recipient=request.recipient,
            subject=request.subject,
            body=request.body,
            status="DRAFT",
            created_at=created_at,
        )

    def _approved_document_path(self, document_id: str) -> Path:
        """Resolve a fixed file and confirm it remains inside the approved root."""
        filename = DOCUMENT_FILES.get(document_id)
        if filename is None:
            raise ToolInputError("document_id is not approved")

        try:
            resolved_path = (self._document_root / filename).resolve(strict=True)
            resolved_path.relative_to(self._document_root)
        except (OSError, ValueError) as error:
            raise ToolExecutionError("Approved document path is unavailable or unsafe.") from error

        return resolved_path

    @staticmethod
    def _validate(model: type[ModelType], data: dict[str, object]) -> ModelType:
        """Convert Pydantic validation failures into the tool's public error type."""
        try:
            return model.model_validate(data)
        except ValidationError as error:
            raise ToolInputError("tool input is invalid") from error
