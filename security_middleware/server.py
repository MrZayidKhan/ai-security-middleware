"""Start the installed, loopback-only prompt security gateway."""

from __future__ import annotations

import argparse
from pathlib import Path


def default_audit_db() -> Path:
    return Path.home() / ".ai-security-middleware" / "security_events.db"


def main(*, default_db: Path | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--audit-db", type=Path, default=default_db or default_audit_db(),
                        help="SQLite file for security events.")
    parser.add_argument("--detector", choices=("existing", "english-verifier", "offline"), default="existing",
                        help="Select a verifier or run the offline sanitation API.")
    parser.add_argument("--model-dir", type=Path, help="Bundled Horizon model directory for offline mode.")
    parser.add_argument("--ollama-cli", action="store_true", help="Enable text-only Ollama CLI compatibility.")
    parser.add_argument("--demo", action="store_true",
                        help="Use the English verifier and short replies from qwen3.5:0.8b.")
    args = parser.parse_args()
    if args.detector == "offline":
        if args.model_dir is None or not args.model_dir.is_dir():
            parser.error("--detector offline requires an existing --model-dir")
        if args.demo or args.ollama_cli:
            parser.error("offline mode provides /api/sanitize and cannot use --demo or --ollama-cli")
    elif args.model_dir is not None:
        parser.error("--model-dir is only valid with --detector offline")
    try:
        import uvicorn
        from .api import create_app
    except ModuleNotFoundError as error:
        if error.name not in {"uvicorn", "fastapi"}:
            raise
        parser.exit(2, 'Install the gateway extras with: python -m pip install "ai-security-middleware[gateway]"\n')

    from .audit_log import AuditLog, initialize_audit_database
    from .content_protection import ContentInspector
    from .ollama_client import OllamaClient
    from .verified_detector import VerifiedDetector

    db = args.audit_db.expanduser().resolve()
    initialize_audit_database(db)
    audit = AuditLog(db)
    if args.detector == "offline":
        from .horizon_detector import HorizonDetector

        try:
            detector = HorizonDetector.from_advisory_profile(args.model_dir)
        except (OSError, ValueError, KeyError, TypeError) as error:
            parser.error(f"Could not load the offline detector profile: {error}")
        app = create_app(
            inspector=ContentInspector(detector=detector, classify_sanitized_text=True),
            audit=audit,
            detector_label="rules+horizon-small-offline",
            sanitize_only=True,
        )
    elif args.detector == "english-verifier" or args.demo:
        model = "qwen3.5:0.8b" if args.demo else "qwen3.5:4b"
        client = None
        if args.demo:
            client = OllamaClient(model_name=model, generation_options={"num_ctx": 4096, "num_predict": 64})
        app = create_app(
            inspector=ContentInspector(detector=VerifiedDetector()),
            client=client,
            audit=audit,
            answer_model=model,
            detector_label="rules+english-contextual-verifier",
            ollama_cli=args.ollama_cli,
            demo_screening=args.demo,
        )
    else:
        app = create_app(audit=audit, ollama_cli=args.ollama_cli)
    uvicorn.run(app, host="127.0.0.1", port=args.port, access_log=False)
