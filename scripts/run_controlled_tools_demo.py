"""Run local demonstrations for the controlled document, database, and outbox tools."""

from pathlib import Path

from security_middleware.controlled_tools import ControlledTools, initialize_demo_databases


def main() -> None:
    """Create synthetic runtime data and perform one safe operation for each tool."""
    project_root = Path(__file__).resolve().parents[1]
    runtime_root = project_root / "runtime_data"
    initialize_demo_databases(
        runtime_root / "project_records.db", runtime_root / "outbox.db"
    )
    tools = ControlledTools(
        project_root / "sample_data" / "documents",
        runtime_root / "project_records.db",
        runtime_root / "outbox.db",
    )

    print("Document search:", tools.search_documents("security"))
    print("Document read:", tools.read_document("project-overview").document_id)
    print("Project record:", tools.get_project_record(1))
    print(
        "Simulated draft:",
        tools.draft_message(
            "project-team@example.test",
            "Controlled tools demonstration",
            "This message is stored locally and is not sent.",
        ),
    )


if __name__ == "__main__":
    main()
