"""Tests for locally stored, content-minimized security events."""

from pathlib import Path

from security_middleware.audit_log import AuditLog, initialize_audit_database


def test_audit_log_stores_and_returns_event_metadata(tmp_path: Path) -> None:
    database_path = tmp_path / "events.db"
    initialize_audit_database(database_path)
    audit_log = AuditLog(database_path)

    event = audit_log.record(
        "content_inspection",
        "Suspicious content was held.",
        {"content_id": "synthetic-case", "finding_count": 1},
        task_id="task-1",
        decision="HOLD_FOR_REVIEW",
    )

    recent = audit_log.recent()
    assert recent[0] == event
    assert "content" not in recent[0].details
