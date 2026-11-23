"""Stdio ACP adapter that checks text before an agent receives it."""

import argparse
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
from contextlib import closing
from pathlib import Path
from uuid import uuid4

from security_middleware.audit_log import AuditLog, initialize_audit_database
from security_middleware.content_protection import (
    ContentDecision, ContentEnvelope, ContentInspector, prompt_policy_outcome,
)
from security_middleware.horizon_detector import HorizonDetector


REVIEW_SECONDS = 120
MAX_TEXT = 20_000
MAX_PENDING = 8


class Guard:
    def __init__(self, inspector, database, to_agent, to_editor):
        self.inspector = inspector
        self.database = database
        self.audit = AuditLog(database)
        self.to_agent = to_agent
        self.to_editor = to_editor
        self.pending = {}
        self.lock = threading.Lock()
        self.inspect_lock = threading.Lock()
        initialize_audit_database(database)
        with closing(sqlite3.connect(database)) as db, db:
            db.execute("""CREATE TABLE IF NOT EXISTS acp_reviews (
                token TEXT PRIMARY KEY, expires_at INTEGER NOT NULL,
                state TEXT NOT NULL, draft TEXT
            )""")
            db.execute("DELETE FROM acp_reviews WHERE expires_at <= unixepoch()")

    def error(self, request, message):
        self.to_editor({"jsonrpc": "2.0", "id": request["id"],
                        "error": {"code": -32001, "message": message}})

    def inspect(self, text):
        with self.inspect_lock:
            return self.inspector.inspect(ContentEnvelope(
                source_id="acp-prompt", content_id=str(uuid4()), content=text,
                origin_trust="untrusted", data_sensitivity="confidential",
                input_channel="direct_user",
            ))

    def record(self, text, result, token=None):
        held = result.decision == ContentDecision.HOLD_FOR_REVIEW
        details = {"origin": "acp_prompt", "content_decisions": [result.decision.value]}
        if result.decision != ContentDecision.PASS:
            details["prompt_review"] = {
                "original": text, "cleaned": result.sanitized_content,
                "decision": prompt_policy_outcome(result),
                "findings": [finding.model_dump() for finding in result.findings],
                "classifier_risk": [output.risk for output in result.detector_outputs],
                "acp_token": token,
            }
        self.audit.record("middleware_inspection", "ACP prompt inspected.", details,
                          decision=prompt_policy_outcome(result) if held else "RELEASED")

    def forward(self, request, cleaned=None):
        if not cleaned:
            self.error(request, "Inspection produced no text to send.")
            return
        request = dict(request, params=dict(request["params"], prompt=[{"type": "text", "text": cleaned}]))
        self.to_agent(request)

    def handle(self, request):
        method = request.get("method")
        if method == "session/cancel":
            params = request.get("params")
            session = params.get("sessionId") if isinstance(params, dict) else None
            if not isinstance(session, str):
                return
            with self.lock:
                pending = self.pending.pop(session, None)
                if pending:
                    token, prompt = pending
                    self.close_review(token)
                    self.to_editor({"jsonrpc": "2.0", "id": prompt["id"],
                                    "result": {"stopReason": "cancelled"}})
                else:
                    self.to_agent(request)
            return
        if method != "session/prompt":
            self.to_agent(request)
            return
        if "id" not in request:
            return
        params = request.get("params")
        session = params.get("sessionId") if isinstance(params, dict) else None
        blocks = params.get("prompt") if isinstance(params, dict) else None
        if (not isinstance(session, str) or not session or not isinstance(blocks, list)
                or not blocks or any(not isinstance(b, dict) or b.get("type") != "text"
                                    or not isinstance(b.get("text"), str) for b in blocks)):
            self.error(request, "Protected ACP accepts text prompts only.")
            return
        # A single inspected string is also the exact string sent downstream.
        text = "\n".join(block["text"] for block in blocks)
        if not text.strip() or len(text) > MAX_TEXT:
            self.error(request, "Prompt must contain 1 to 20,000 characters.")
            return
        result = self.inspect(text)
        with self.lock:
            if session in self.pending:
                self.error(request, "This session already has a pending review.")
                return
            if result.decision != ContentDecision.HOLD_FOR_REVIEW:
                self.record(text, result)
                self.forward(request, result.sanitized_content)
                return
            if prompt_policy_outcome(result) == "MALICIOUS_BLOCKED":
                self.record(text, result)
                self.error(request, "Malicious prompt blocked by policy.")
                return
            if len(self.pending) >= MAX_PENDING:
                self.error(request, "Too many pending reviews. Cancel one and retry.")
                return
            token = uuid4().hex
            expires = int(time.time()) + REVIEW_SECONDS
            with closing(sqlite3.connect(self.database)) as db, db:
                db.execute("INSERT INTO acp_reviews VALUES (?, ?, 'pending', NULL)", (token, expires))
            try:
                self.record(text, result, token)
            except Exception:
                self.close_review(token)
                raise
            self.pending[session] = (token, request)
            threading.Thread(target=self.wait_for_review, args=(session, token, request, expires),
                             daemon=True).start()
            print("ACP prompt held. Open the security dashboard to review it.", file=sys.stderr, flush=True)

    def close_review(self, token):
        with closing(sqlite3.connect(self.database)) as db, db:
            db.execute("DELETE FROM acp_reviews WHERE token = ?", (token,))

    def close(self):
        with self.lock:
            pending = list(self.pending.values())
            self.pending.clear()
            if pending:
                with closing(sqlite3.connect(self.database)) as db, db:
                    db.executemany("DELETE FROM acp_reviews WHERE token = ?",
                                   [(token,) for token, _ in pending])

    def wait_for_review(self, session, token, request, expires):
        result = None
        draft = None
        try:
            while time.time() < expires:
                with closing(sqlite3.connect(self.database)) as db:
                    row = db.execute("SELECT state, draft FROM acp_reviews WHERE token = ?", (token,)).fetchone()
                if row is None:
                    break
                if row[0] == "approved":
                    draft = row[1]
                    if isinstance(draft, str) and draft.strip() and len(draft) <= MAX_TEXT:
                        result = self.inspect(draft)
                    break
                time.sleep(0.25)
            with self.lock:
                if self.pending.get(session, (None,))[0] != token:
                    return
                self.close_review(token)
                if result is not None and time.time() < expires:
                    self.record(draft, result)
                    if time.time() < expires and result.decision != ContentDecision.HOLD_FOR_REVIEW:
                        self.forward(request, result.sanitized_content)
                        self.pending.pop(session)
                        return
                self.error(request, "Review expired or edited text did not pass inspection. Submit a new draft.")
                self.pending.pop(session)
        except (OSError, sqlite3.Error, ValueError):
            with self.lock:
                if self.pending.get(session, (None,))[0] == token:
                    self.pending.pop(session)
                    self.error(request, "Prompt review failed.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent", choices=("antigravity", "codex"), required=True)
    parser.add_argument("--model-dir", type=Path, required=True)
    parser.add_argument("--audit-db", type=Path, required=True)
    args = parser.parse_args()
    name = "agy" if args.agent == "antigravity" else "codex-acp"
    executable = next(
        (match for entry in os.get_exec_path() if Path(entry).is_absolute()
         if (match := shutil.which(str(Path(entry) / name))) is not None),
        None,
    )
    if not executable:
        parser.error(f"Install {name} and add it to PATH.")
    detector = HorizonDetector.from_advisory_profile(args.model_dir)
    inspector = ContentInspector(detector=detector, classify_sanitized_text=True)
    command = [executable, "acp"] if args.agent == "antigravity" else [executable]
    child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    def sender(stream):
        lock = threading.Lock()

        def send(message):
            line = (json.dumps(message, ensure_ascii=True) + "\n").encode("ascii")
            with lock:
                stream.write(line)
                stream.flush()
        return send

    try:
        guard = Guard(inspector, args.audit_db, sender(child.stdin), sender(sys.stdout.buffer))

        def read_editor():
            try:
                for line in sys.stdin.buffer:
                    message = json.loads(line)
                    if not isinstance(message, dict):
                        continue
                    try:
                        guard.handle(message)
                    except (OSError, sqlite3.Error, ValueError):
                        if "id" in message:
                            guard.error(message, "Local prompt inspection failed.")
            finally:
                try:
                    guard.close()
                finally:
                    if child.poll() is None:
                        child.terminate()

        threading.Thread(target=read_editor, daemon=True).start()
        for line in child.stdout:
            guard.to_editor(json.loads(line))
        return child.wait()
    finally:
        if child.poll() is None:
            child.terminate()
            child.wait()


if __name__ == "__main__":
    raise SystemExit(main())
