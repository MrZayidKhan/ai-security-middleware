"""Tests for narrow filesystem, SQLite, and simulated-outbox operations."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from security_middleware.controlled_tools import (
    ControlledTools,
    ToolInputError,
    initialize_demo_databases,
)


@pytest.fixture
def tools(tmp_path: Path) -> ControlledTools:
    project_root = Path(__file__).resolve().parents[1]
    database_path = tmp_path / "records.db"
    outbox_path = tmp_path / "outbox.db"
    initialize_demo_databases(database_path, outbox_path)
    return ControlledTools(
        project_root / "sample_data" / "documents", database_path, outbox_path
    )


def test_search_and_read_use_approved_document_ids(tools: ControlledTools) -> None:
    matches = tools.search_documents("security")

    assert [match.document_id for match in matches] == ["project-overview", "security-scope"]
    assert "application-level" in tools.read_document("security-scope").content


def test_unknown_document_id_is_rejected(tools: ControlledTools) -> None:
    with pytest.raises(ToolInputError, match="not approved"):
        tools.read_document("../../private.txt")


def test_project_record_uses_fixed_parameterized_lookup(tools: ControlledTools) -> None:
    record = tools.get_project_record(1)

    assert record is not None
    assert record.title == "Middleware design"
    with pytest.raises(ToolInputError):
        tools.get_project_record(0)


def test_simulated_outbox_stores_but_never_sends(tools: ControlledTools, tmp_path: Path) -> None:
    draft = tools.draft_message(
        "project-team@example.test", "Test draft", "Stored locally only."
    )

    assert draft.status == "DRAFT"
    outbox_path = tmp_path / "outbox.db"
    with sqlite3.connect(outbox_path) as connection:
        stored_recipient = connection.execute(
            "SELECT recipient FROM outbox_drafts WHERE draft_id = ?", (draft.draft_id,)
        ).fetchone()[0]
    assert stored_recipient == "project-team@example.test"


def test_unapproved_recipient_is_rejected(tools: ControlledTools) -> None:
    with pytest.raises(ToolInputError, match="not approved"):
        tools.draft_message("outside@example.test", "Test", "This must not be stored.")
