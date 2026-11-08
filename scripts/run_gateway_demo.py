"""Demonstrate allowed and blocked controlled-tool requests through the gateway."""

from pathlib import Path

from security_middleware.action_gateway import ActionGateway
from security_middleware.controlled_tools import ControlledTools, initialize_demo_databases


def main() -> None:
    """Run one allowed read and one blocked recipient request."""
    project_root = Path(__file__).resolve().parents[1]
    runtime_root = project_root / "runtime_data"
    initialize_demo_databases(
        runtime_root / "project_records.db", runtime_root / "outbox.db"
    )
    gateway = ActionGateway(
        ControlledTools(
            project_root / "sample_data" / "documents",
            runtime_root / "project_records.db",
            runtime_root / "outbox.db",
        )
    )

    allowed = gateway.handle(
        {
            "task_id": "gateway-demo",
            "tool_name": "read_approved_document",
            "arguments": {"document_id": "project-overview"},
        }
    )
    blocked = gateway.handle(
        {
            "task_id": "gateway-demo",
            "tool_name": "draft_local_message",
            "arguments": {
                "recipient": "outside@example.test",
                "subject": "Blocked message",
                "body": "This must never be stored.",
            },
        }
    )

    print("Allowed request:", allowed.decision, allowed.execution_outcome)
    print("Blocked request:", blocked.decision, blocked.reason)


if __name__ == "__main__":
    main()
