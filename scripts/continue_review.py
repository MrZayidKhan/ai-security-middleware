"""Explicitly send a rechecked approved excerpt and task to local Ollama."""
import argparse
from pathlib import Path

from security_middleware.audit_log import AuditLog, initialize_audit_database
from security_middleware.content_assessor import OllamaContentAssessor
from security_middleware.content_protection import ContentInspector
from security_middleware.ollama_client import OllamaClient
from security_middleware.protected_demo import run_reviewed_demo
from security_middleware.review_queue import ReviewQueue


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('review_id', type=int)
    parser.add_argument('--task', required=True)
    parser.add_argument('--send-to-model', action='store_true', required=True,
                        help='Explicitly authorize the local answering-model request')
    args = parser.parse_args()
    runtime = Path(__file__).resolve().parents[1]/'runtime_data'
    if not (runtime/'reviews.db').is_file():
        parser.error('Review database is missing.')
    inspector = ContentInspector(assessor=OllamaContentAssessor(), require_assessment_for_untrusted=True)
    try:
        receipt = run_reviewed_demo(args.task, args.review_id, ReviewQueue(runtime/'reviews.db'),
                                    inspector, OllamaClient())
    except ValueError as error:
        parser.error(str(error))
    initialize_audit_database(runtime/'security_events.db')
    AuditLog(runtime/'security_events.db').record('review_continuation', receipt.reason,
        {'review_id': args.review_id, 'model_called': receipt.model_called,
         'forwarded_sha256': receipt.forwarded_sha256, 'error': receipt.error},
        decision=receipt.decision)
    print(receipt.model_dump_json(indent=2))


if __name__ == '__main__':
    main()
