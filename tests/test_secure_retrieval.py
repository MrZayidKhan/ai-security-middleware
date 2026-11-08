"""Tests for the end-to-end protected document-retrieval path."""

from __future__ import annotations

from pathlib import Path

import pytest

from security_middleware.action_gateway import ActionDecision, ActionGateway
from security_middleware.content_protection import ContentDecision, ContentInspector
from security_middleware.controlled_tools import ControlledTools, initialize_demo_databases
from security_middleware.review_queue import ReviewQueue, initialize_review_database
from security_middleware.secure_retrieval import SecureDocumentRetrieval


@pytest.fixture
def retrieval(tmp_path: Path) -> SecureDocumentRetrieval:
    project_root = Path(__file__).resolve().parents[1]
    database_path = tmp_path / "records.db"
    outbox_path = tmp_path / "outbox.db"
    review_path = tmp_path / "reviews.db"
    initialize_demo_databases(database_path, outbox_path)
    initialize_review_database(review_path)
    return SecureDocumentRetrieval(
        ActionGateway(
            ControlledTools(
                project_root / "sample_data" / "documents", database_path, outbox_path
            )
        ),
        ContentInspector(),
        ReviewQueue(review_path),
    )


def test_sanitized_document_returns_safe_replacement(retrieval: SecureDocumentRetrieval) -> None:
    result = retrieval.retrieve("task-sanitize", "sanitizable-instruction")

    assert result.action.decision is ActionDecision.ALLOW
    assert result.inspection.decision is ContentDecision.SANITIZE
    assert "Suspicious instruction removed" in result.content_for_model
    assert result.review_id is None


def test_high_risk_document_is_held_after_gateway_allows_read(
    retrieval: SecureDocumentRetrieval,
) -> None:
    result = retrieval.retrieve("task-hold", "untrusted-injection")

    assert result.action.decision is ActionDecision.ALLOW
    assert result.inspection.decision is ContentDecision.HOLD_FOR_REVIEW
    assert result.content_for_model is None
    assert result.review_id is not None


def test_invalid_document_id_is_blocked_before_content_inspection(
    retrieval: SecureDocumentRetrieval,
) -> None:
    result = retrieval.retrieve("task-block", "../../private.txt")

    assert result.action.decision is ActionDecision.BLOCK
    assert result.inspection is None
