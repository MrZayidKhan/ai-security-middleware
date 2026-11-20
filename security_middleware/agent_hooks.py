"""Install and run workspace prompt-security hooks for supported coding agents."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shlex
import sys
from tempfile import NamedTemporaryFile


HOOK_DIRECTORY = {"codex": ".codex", "antigravity": ".agents"}
HOOK_GROUP = "ai-security-middleware"
MAX_PAYLOAD_BYTES = 1_048_576
OLLAMA_REQUEST_TIMEOUT_SECONDS = 90
OLLAMA_HOOK_TIMEOUT_SECONDS = 110


def record_inspection(audit_db: Path, event: str, detector: str, released: bool, reason: str) -> None:
    try:
        from security_middleware.audit_log import AuditLog, initialize_audit_database

        initialize_audit_database(audit_db)
        AuditLog(audit_db).record(
            "hook_inspection",
            reason,
            {
                "agent": "antigravity" if event == "antigravity-prompt" else "codex",
                "origin": "tool_result" if event == "codex-result" else "user_prompt",
                "hook_event": event,
                "detector": detector,
            },
            decision="RELEASED" if released else "BLOCKED",
        )
    except Exception:
        # Audit availability must not change the enforcement decision or hook output.
        pass


def screen(event: str, detector: str, audit_db: Path | None = None, model_dir: Path | None = None) -> dict:
    reason = "Prompt security inspection unavailable."
    released = False
    try:
        # Keep imports inside the handler so dependency errors also produce a block.
        from security_middleware.content_assessor import ModelAssessment, OllamaContentAssessor
        from security_middleware.content_protection import ContentDecision, ContentInspector
        from security_middleware.middleware import PromptSecurityMiddleware
        from security_middleware.models import ChatMessage
        from security_middleware.ollama_client import OllamaClient

        raw = sys.stdin.buffer.read(MAX_PAYLOAD_BYTES + 1)
        if len(raw) > MAX_PAYLOAD_BYTES:
            raise ValueError("Hook payload too large")
        payload = json.loads(raw)
        is_tool_result = event == "codex-result"
        if is_tool_result:
            content = payload["tool_response"]
            if content is None or content == "":
                released = True
                reason = "Empty tool result required no screening."
                return {}
            if not isinstance(content, str):
                content = json.dumps(content, ensure_ascii=False, indent=2)
        elif event == "antigravity-prompt":
            content = payload["lastUserInput"]
        else:
            content = payload["prompt"]
        if not isinstance(content, str):
            raise ValueError("Expected text")

        assessor = None
        classifier = None
        if detector == "offline":
            from security_middleware.horizon_detector import HorizonDetector

            if model_dir is None:
                raise ValueError("Offline detector requires a model directory")
            classifier = HorizonDetector.from_advisory_profile(model_dir)
        if detector == "ollama":
            # Leave time for a cold model load while still returning a decision before the host deadline.
            client = OllamaClient(timeout_seconds=OLLAMA_REQUEST_TIMEOUT_SECONDS,
                                  response_format=ModelAssessment.model_json_schema())
            assessor = OllamaContentAssessor(client)
        middleware = PromptSecurityMiddleware(
            ContentInspector(assessor=assessor, require_assessment_for_untrusted=detector == "ollama",
                             detector=classifier)
        )
        role = "tool" if is_tool_result else "user"
        result = middleware.before_model([ChatMessage(role=role, content=content)])
        decision = result.content_decisions[0]
        if decision is ContentDecision.PASS:
            released = True
            reason = "Prompt security inspection passed."
            return {}
        if decision is ContentDecision.SANITIZE:
            reason = "Prompt security withheld text that requires sanitization."
        else:
            reason = "Prompt security withheld text for review."
    except Exception:
        # Payloads and classifier reasons may contain the text being withheld.
        pass
    finally:
        if audit_db is not None:
            record_inspection(audit_db, event, detector, released, reason)

    if event == "antigravity-prompt":
        return {
            "terminationBehavior": "terminate",
            "injectSteps": [{"errorMessage": {"userMessage": reason}}],
        }
    return {"decision": "block", "reason": reason}


def command_for(event: str, detector: str, shell: str, audit_db: Path | None = None,
                model_dir: Path | None = None) -> dict:
    executable = str(Path(sys.executable).absolute())
    args = ["-m", "security_middleware.agent_hooks", "hook", event, "--detector", detector]
    options = [(flag, str(path)) for flag, path in
               (("--audit-db", audit_db), ("--model-dir", model_dir)) if path is not None]
    if shell == "powershell":
        command = "& '" + executable.replace("'", "''") + "' " + " ".join(args)
        for flag, value in options:
            command += f" {flag} '" + value.replace("'", "''") + "'"
    elif shell == "cmd":
        paths = [executable, *(value for _, value in options)]
        if any(set(path).intersection('%!"\r\n') for path in paths):
            raise ValueError("CMD hook paths cannot contain %, !, quotes, or newlines.")
        command = f'"{executable}" ' + " ".join(args)
        for flag, value in options:
            command += f' {flag} "{value}"'
    else:
        for flag, value in options:
            args.extend([flag, value])
        command = shlex.join([executable, *args])
    timeout = OLLAMA_HOOK_TIMEOUT_SECONDS if detector == "ollama" else 45
    return {"type": "command", "command": command, "timeout": timeout}


def configure(
    agent: str, workspace: Path, detector: str, shell: str | None = None, audit_db: Path | None = None,
    model_dir: Path | None = None,
) -> Path:
    workspace = workspace.resolve(strict=True)
    if not workspace.is_dir():
        raise ValueError("Workspace must be a directory.")
    if shell is None:
        shell = ("cmd" if agent == "antigravity" else "powershell") if os.name == "nt" else "posix"
    if audit_db is not None:
        audit_db = (workspace / audit_db).resolve()
    if detector == "offline":
        if model_dir is None or not (workspace / model_dir).is_dir():
            raise ValueError("Supply an installed offline model directory with --model-dir.")
        model_dir = (workspace / model_dir).resolve()
    directory = workspace / HOOK_DIRECTORY[agent]
    path = directory / "hooks.json"
    if directory.is_symlink() or path.is_symlink() or not path.resolve().is_relative_to(workspace):
        raise ValueError("Hook configuration must reside inside the workspace.")
    config = json.loads(path.read_text(encoding="utf-8-sig")) if path.exists() else {}
    if not isinstance(config, dict):
        raise ValueError("Existing hooks.json must contain a JSON object.")
    if agent == "codex":
        hooks = config.setdefault("hooks", {})
        if not isinstance(hooks, dict):
            raise ValueError("Existing Codex hooks must contain a JSON object.")
        for name, event in [("UserPromptSubmit", "codex-prompt"), ("PostToolUse", "codex-result")]:
            groups = hooks.setdefault(name, [])
            if not isinstance(groups, list):
                raise ValueError(f"Existing {name} hooks must contain an array.")
            # Match only handlers previously generated by this installer.
            marker = f"-m security_middleware.agent_hooks hook {event} --detector "
            for group in groups:
                for handler in group.get("hooks", []):
                    if marker in handler.get("command", ""):
                        handler.update(command_for(event, detector, shell, audit_db, model_dir))
                        break
                else:
                    continue
                break
            else:
                groups.append({"hooks": [command_for(event, detector, shell, audit_db, model_dir)]})
    else:
        config[HOOK_GROUP] = {"PreInvocation": [command_for("antigravity-prompt", detector, shell, audit_db, model_dir)]}

    directory.mkdir(exist_ok=True)
    temp_path = None
    try:
        with NamedTemporaryFile(mode="w", encoding="utf-8", dir=directory, delete=False) as temp:
            temp_path = Path(temp.name)
            json.dump(config, temp, indent=2, ensure_ascii=False)
            temp.write("\n")
        temp_path.replace(path)
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    install = sub.add_parser("install", help="Install hooks in one workspace")
    install.add_argument("agent", choices=HOOK_DIRECTORY)
    install.add_argument("--workspace", type=Path, default=Path.cwd())
    install.add_argument("--shell", choices=["posix", "powershell", "cmd"],
                         help="Override the native hook shell for this agent and platform.")
    hook = sub.add_parser("hook", help="Process one JSON event from stdin")
    hook.add_argument("event", choices=["codex-prompt", "codex-result", "antigravity-prompt"])
    for command in (install, hook):
        command.add_argument("--detector", choices=["ollama", "rules", "offline"], default="ollama")
        command.add_argument("--model-dir", type=Path, help="Directory containing the offline classifier.")
        command.add_argument("--audit-db", type=Path, help="Record decisions in the shared security-events database.")
    args = parser.parse_args()
    if args.mode == "hook":
        print(json.dumps(screen(args.event, args.detector, args.audit_db, args.model_dir)))
    else:
        try:
            print(configure(args.agent, args.workspace, args.detector, args.shell, args.audit_db, args.model_dir))
        except (ValueError, OSError, TypeError, AttributeError) as error:
            parser.exit(1, f"Could not install hooks: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
