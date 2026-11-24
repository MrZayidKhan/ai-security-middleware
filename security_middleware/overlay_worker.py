"""Private stdio detector process for the Windows Protected Send overlay."""

import argparse
import json
import sys
from pathlib import Path

from security_middleware.connector_service import ConnectorService
from security_middleware.content_protection import ContentInspector
from security_middleware.horizon_detector import HorizonDetector


def reply(service, request):
    if not isinstance(request, dict):
        raise ValueError("Invalid request.")
    operation = request.get("operation")
    fields = {"inspect": "text", "poll": "ticket", "cancel": "ticket"}
    if operation == "ping" and set(request) == {"operation"}:
        return {"state": "available"}
    if not isinstance(operation, str) or operation not in fields:
        raise ValueError("Invalid operation.")
    field = fields[operation]
    if set(request) != {"operation", "target", field}:
        raise ValueError("Invalid request fields.")
    handler = {"inspect": service.inspect, "poll": service.poll, "cancel": service.cancel}[operation]
    return handler(request[field], request["target"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-dir", required=True, type=Path)
    parser.add_argument("--audit-db", required=True, type=Path)
    args = parser.parse_args()
    try:
        detector = HorizonDetector.from_advisory_profile(args.model_dir)
        inspector = ContentInspector(detector=detector, classify_sanitized_text=True, mark_redactions=False)
        args.audit_db.parent.mkdir(parents=True, exist_ok=True)
        service = ConnectorService(inspector, args.audit_db, include_evidence=True, allow_review=False)
    except Exception:
        print("Local Protected Send could not initialize.", file=sys.stderr)
        return 1
    while frame := sys.stdin.buffer.readline(512 * 1024 + 1):
        if len(frame) > 512 * 1024:
            return 1
        try:
            result = reply(service, json.loads(frame))
        except Exception:
            result = {"state": "error", "reason": "Local inspection failed. Nothing was sent."}
        print(json.dumps(result), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
