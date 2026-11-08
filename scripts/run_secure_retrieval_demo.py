"""Demonstrate PASS, SANITIZE, and HOLD decisions after gateway-protected reads."""

from pathlib import Path

from security_middleware.action_gateway import ActionGateway
from security_middleware.content_protection import ContentInspector
from security_middleware.controlled_tools import ControlledTools, initialize_demo_databases
from security_middleware.review_queue import ReviewQueue, initialize_review_database
from security_middleware.secure_retrieval import SecureDocumentRetrieval


def main() -> None:
    """Retrieve three synthetic documents through the secure content path."""
    project_root = Path(__file__).resolve().parents[1]
    runtime_root = project_root / "runtime_data"
    initialize_demo_databases(
        runtime_root / "project_records.db", runtime_root / "outbox.db"
    )
    initialize_review_database(runtime_root / "reviews.db")
    retrieval = SecureDocumentRetrieval(
        ActionGateway(
            ControlledTools(
                project_root / "sample_data" / "documents",
                runtime_root / "project_records.db",
                runtime_root / "outbox.db",
            )
        ),
        ContentInspector(),
        ReviewQueue(runtime_root / "reviews.db"),
    )

    for document_id in (
        "project-overview",
        "sanitizable-instruction",
        "untrusted-injection",
    ):
        result = retrieval.retrieve(f"secure-retrieval-{document_id}", document_id)
        print(
            document_id,
            result.action.decision,
            result.inspection.decision if result.inspection else None,
            f"review_id={result.review_id}",
        )


if __name__ == "__main__":
    main()
