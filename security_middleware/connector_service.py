"""Transport-neutral local inspection and review for protected chat connectors."""

from __future__ import annotations

import sqlite3
import threading
import time
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from security_middleware.audit_log import AuditLog, initialize_audit_database
from security_middleware.content_protection import (
    ContentDecision,
    ContentEnvelope,
    ContentInspectionResult,
    ContentInspector,
    prompt_policy_outcome,
)

MAX_TEXT = 20_000
MAX_TARGET = 128
MAX_PENDING = 8
REVIEW_SECONDS = 120


@dataclass(frozen=True)
class PendingReview:
    target: str
    expires_at: int


class ConnectorService:
    """Prepare accepted text; the host must verify and submit to its own chat.

    Opaque target IDs are scoped to a connector view. A review expires, is
    single-use, and cannot be claimed from a different target. No method
    submits text or calls an answering agent.
    """

    def __init__(self, inspector: ContentInspector, database: Path, *, include_evidence: bool = False,
                 allow_review: bool = True):
        self._inspector = inspector
        self._database = Path(database)
        self._audit = AuditLog(self._database)
        self._include_evidence = include_evidence
        self._allow_review = allow_review
        self._pending: dict[str, PendingReview] = {}
        self._lock = threading.Lock()
        initialize_audit_database(self._database)
        with closing(sqlite3.connect(self._database)) as db, db:
            # Use the existing Rust dashboard's pending-review storage.
            db.execute("""CREATE TABLE IF NOT EXISTS acp_reviews (
                token TEXT PRIMARY KEY, expires_at INTEGER NOT NULL,
                state TEXT NOT NULL, draft TEXT
            )""")
            db.execute("DELETE FROM acp_reviews WHERE expires_at <= unixepoch()")

    @staticmethod
    def _check_target(target: str) -> None:
        if (not isinstance(target, str) or not target or len(target) > MAX_TARGET
                or any(not char.isascii() or not (char.isalnum() or char in "_-.")
                       for char in target)):
            raise ValueError("A valid connector target is required.")

    @staticmethod
    def _valid_text(text: str) -> bool:
        return isinstance(text, str) and len(text) <= MAX_TEXT and bool(text.strip())

    def _check(self, text: str) -> ContentInspectionResult:
        result = self._inspector.inspect(ContentEnvelope(
            source_id="protected-send", content_id=str(uuid4()), content=text,
            origin_trust="untrusted", data_sensitivity="confidential",
            input_channel="direct_user",
        ))
        if result.decision != ContentDecision.HOLD_FOR_REVIEW and not self._valid_text(result.sanitized_content):
            raise ValueError("Inspection produced no valid text to submit.")
        return result

    def _record(self, original: str, result: ContentInspectionResult, ticket: str | None = None) -> None:
        outcome = prompt_policy_outcome(result)
        details = {"origin": "protected_send", "content_decisions": [result.decision.value]}
        if result.decision != ContentDecision.PASS:
            details["prompt_review"] = {
                "original": original,
                "cleaned": result.sanitized_content if result.decision == ContentDecision.SANITIZE else None,
                "decision": outcome,
                "findings": [finding.model_dump() for finding in result.findings],
                "classifier_risk": [output.risk for output in result.detector_outputs],
                "acp_token": ticket,
            }
        self._audit.record(
            "middleware_inspection", "Protected Send prompt inspected.", details,
            decision=outcome if result.decision == ContentDecision.HOLD_FOR_REVIEW else "RELEASED",
        )

    @staticmethod
    def _uncertain(state: str) -> dict[str, str]:
        return {"decision": "UNCERTAIN", "state": state}

    def _result(self, result: ContentInspectionResult) -> dict[str, str]:
        outcome = prompt_policy_outcome(result)
        if outcome in {"PASS", "SANITIZE"}:
            response = {"decision": outcome, "state": "ready", "text": result.sanitized_content}
            if outcome == "SANITIZE" and self._include_evidence:
                spans = dict.fromkeys(finding.matched_text for finding in result.findings
                                      if finding.rule_id == "instruction-override")
                response["removed"] = "\n".join(spans)[:1200]
            return response
        if outcome == "MALICIOUS_BLOCKED":
            response = {"decision": outcome, "state": "blocked"}
            if self._include_evidence:
                response["reason"] = result.reason
            return response
        return ConnectorService._uncertain("review_rejected")

    def _remove(self, ticket: str) -> None:
        self._pending.pop(ticket, None)
        with closing(sqlite3.connect(self._database)) as db, db:
            db.execute("DELETE FROM acp_reviews WHERE token = ?", (ticket,))

    def _expire(self) -> None:
        now = time.time()
        for ticket, review in list(self._pending.items()):
            if review.expires_at <= now:
                self._remove(ticket)

    def inspect(self, text: str, target: str) -> dict[str, str]:
        self._check_target(target)
        if not self._valid_text(text):
            raise ValueError("Prompt must contain 1 to 20,000 characters.")
        with self._lock:
            self._expire()
            if any(review.target == target for review in self._pending.values()):
                return self._uncertain("busy")
            result = self._check(text)
            if prompt_policy_outcome(result) != "UNCERTAIN":
                self._record(text, result)
                return self._result(result)
            if not self._allow_review:
                self._record(text, result)
                return {**self._uncertain("blocked"), "reason": result.reason}
            if len(self._pending) >= MAX_PENDING:
                self._record(text, result)
                return self._uncertain("busy")
            ticket = uuid4().hex
            expires_at = int(time.time()) + REVIEW_SECONDS
            with closing(sqlite3.connect(self._database)) as db, db:
                db.execute("INSERT INTO acp_reviews VALUES (?, ?, 'pending', NULL)", (ticket, expires_at))
            try:
                self._record(text, result, ticket)
            except Exception:
                self._remove(ticket)
                raise
            self._pending[ticket] = PendingReview(target, expires_at)
            response = {**self._uncertain("pending"), "ticket": ticket}
            if self._include_evidence:
                response["reason"] = result.reason
            return response

    def poll(self, ticket: str, target: str) -> dict[str, str]:
        self._check_target(target)
        with self._lock:
            self._expire()
            review = self._pending.get(ticket) if isinstance(ticket, str) else None
            if review is None or review.target != target:
                return self._uncertain("closed")
            with closing(sqlite3.connect(self._database)) as db:
                row = db.execute("SELECT state, draft FROM acp_reviews WHERE token = ?", (ticket,)).fetchone()
            if row is None:
                self._remove(ticket)
                return self._uncertain("closed")
            state, draft = row
            if state == "pending":
                return {**self._uncertain("pending"), "ticket": ticket}
            # Consume before running the model, even if reinspection fails.
            self._remove(ticket)
            if state != "approved" or not self._valid_text(draft):
                return self._uncertain("review_rejected")
            result = self._check(draft)
            self._record(draft, result)
            if time.time() >= review.expires_at:
                return self._uncertain("closed")
            return self._result(result)

    def cancel(self, ticket: str, target: str) -> dict[str, str]:
        self._check_target(target)
        with self._lock:
            self._expire()
            review = self._pending.get(ticket) if isinstance(ticket, str) else None
            if review is None or review.target != target:
                return self._uncertain("closed")
            self._remove(ticket)
            return self._uncertain("cancelled")
