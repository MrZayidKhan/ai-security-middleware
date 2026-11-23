"""Inspect a local prompt before submitting it to a supported agent CLI."""

import argparse
import json
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

from security_middleware.audit_log import AuditLog, initialize_audit_database
from security_middleware.content_protection import (
    ContentDecision, ContentEnvelope, ContentInspector, prompt_policy_outcome,
)
from security_middleware.horizon_detector import HorizonDetector


def submit(agent, executable, workspace, prompt):
    if agent == "codex":
        return subprocess.run(
            [executable, "-c", 'approval_policy="never"', "exec", "--sandbox", "read-only",
             "--skip-git-repo-check", "-"],
            input=prompt, encoding="utf-8", cwd=workspace,
        ).returncode

    message = {"event": "user", "message": {"content": prompt}}
    result = subprocess.run(
        [executable, "--mode", "default", "--sandbox", "--disable-slash-commands",
         "--input-format", "stream-json", "--output-format", "stream-json", "--print-timeout", "5m"],
        input=json.dumps(message) + "\n", stdout=subprocess.PIPE,
        encoding="utf-8", cwd=workspace,
    )
    if result.returncode:
        return result.returncode
    for line in reversed(result.stdout.splitlines()):
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict) and event.get("event") == "result":
            outcome = event.get("result")
            if not isinstance(outcome, dict):
                continue
            response = outcome.get("response")
            if outcome.get("is_error") or outcome.get("status") in {"ERROR", "FAILED"}:
                print("Antigravity reported a failed turn.", file=sys.stderr)
                return 1
            if isinstance(response, str):
                print(response)
                return 0
    print("Antigravity finished without a readable response.", file=sys.stderr)
    return 1


def run_turn(agent, executable, workspace, prompt, inspector, audit):
    result = inspector.inspect(ContentEnvelope(
        source_id=f"protected-agent:{agent}", content_id=str(uuid4()),
        origin_trust="untrusted", data_sensitivity="confidential",
        input_channel="direct_user", content=prompt,
    ))
    blocked = result.decision == ContentDecision.HOLD_FOR_REVIEW or not result.sanitized_content
    details = {"agent": agent, "content_decisions": [result.decision.value]}
    if result.decision != ContentDecision.PASS and len(prompt) <= 20_000:
        details["prompt_review"] = {
            "original": prompt,
            "cleaned": None if blocked else result.sanitized_content,
            "decision": prompt_policy_outcome(result),
            "findings": [finding.model_dump() for finding in result.findings],
            "classifier_risk": [output.risk for output in result.detector_outputs],
        }
    audit.record("middleware_inspection", "Protected agent prompt inspected.", details,
                 decision=prompt_policy_outcome(result) if blocked else "RELEASED")
    if blocked:
        print(f"{prompt_policy_outcome(result)} — prompt withheld.", file=sys.stderr)
        return 3
    print(f"{result.decision.value} — sending inspected text to {agent}.", file=sys.stderr, flush=True)
    return submit(agent, executable, workspace, result.sanitized_content)


def read_prompt():
    print("Paste your prompt. Enter /send on its own line to submit.")
    lines = []
    size = 0
    while True:
        line = input()
        if line == "/send":
            return "\n".join(lines)
        size += len(line) + 1
        if size > 20_001:
            raise ValueError("Prompt exceeds 20,000 characters.")
        lines.append(line)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-dir", type=Path, required=True)
    parser.add_argument("--audit-db", type=Path, required=True)
    parser.add_argument("--agent", choices=("codex", "antigravity"))
    parser.add_argument("--workspace", type=Path)
    args = parser.parse_args()
    try:
        agent = args.agent or {"1": "codex", "2": "antigravity"}.get(
            input("Choose 1 for Codex or 2 for Antigravity: ").strip())
        if not agent:
            raise ValueError("Choose one of the supported agents.")
        executable = shutil.which("codex" if agent == "codex" else "agy")
        if executable is None:
            raise ValueError(f"Install the {agent} CLI, sign in, and make it available on PATH.")
        workspace = args.workspace or Path(input("Workspace folder: ").strip().strip('"'))
        workspace = workspace.resolve(strict=True)
        if not workspace.is_dir():
            raise ValueError("The workspace must be a directory.")
        prompt = read_prompt()
        detector = HorizonDetector.from_advisory_profile(args.model_dir)
        inspector = ContentInspector(detector=detector, classify_sanitized_text=True)
        initialize_audit_database(args.audit_db)
        return run_turn(agent, executable, workspace, prompt, inspector, AuditLog(args.audit_db))
    except (EOFError, KeyboardInterrupt):
        return 130
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error) as error:
        print(f"Protected launcher failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
