"""Tests for independent authorization before controlled tool execution."""

from __future__ import annotations

from pathlib import Path

import pytest

from security_middleware.action_gateway import (
    ActionDecision,
    ActionGateway,
    ExecutionOutcome,
    GatewayPolicy,
)
from security_middleware.controlled_tools import ControlledTools, initialize_demo_databases


@pytest.fixture
def gateway(tmp_path: Path) -> ActionGateway:
    project_root = Path(__file__).resolve().parents[1]
    database_path = tmp_path / "records.db"
    outbox_path = tmp_path / "outbox.db"
    initialize_demo_databases(database_path, outbox_path)
    tools = ControlledTools(
        project_root / "sample_data" / "documents", database_path, outbox_path
    )
    return ActionGateway(tools)


def test_allowed_document_read_executes_through_gateway(gateway: ActionGateway) -> None:
    result = gateway.handle(
        {
            "task_id": "task-1",
            "tool_name": "read_approved_document",
            "arguments": {"document_id": "project-overview"},
        }
    )

    assert result.decision is ActionDecision.ALLOW
    assert result.execution_outcome is ExecutionOutcome.SUCCEEDED
    assert result.result["document_id"] == "project-overview"


def test_unknown_tool_is_blocked_without_execution(gateway: ActionGateway) -> None:
    result = gateway.handle(
        {"task_id": "task-1", "tool_name": "run_command", "arguments": {}}
    )

    assert result.decision is ActionDecision.BLOCK
    assert result.execution_outcome is ExecutionOutcome.NOT_EXECUTED
    assert "allowlisted" in result.reason


def test_extra_or_malformed_arguments_are_blocked(gateway: ActionGateway) -> None:
    result = gateway.handle(
        {
            "task_id": "task-1",
            "tool_name": "get_project_record",
            "arguments": {"record_id": 1, "sql": "SELECT * FROM project_records"},
        }
    )

    assert result.decision is ActionDecision.BLOCK
    assert "arguments" in result.reason


def test_out_of_scope_document_and_recipient_are_blocked(gateway: ActionGateway) -> None:
    document_result = gateway.handle(
        {
            "task_id": "task-1",
            "tool_name": "read_approved_document",
            "arguments": {"document_id": "../../private.txt"},
        }
    )
    recipient_result = gateway.handle(
        {
            "task_id": "task-1",
            "tool_name": "draft_local_message",
            "arguments": {
                "recipient": "outside@example.test",
                "subject": "Blocked",
                "body": "Do not store this.",
            },
        }
    )

    assert document_result.decision is ActionDecision.BLOCK
    assert recipient_result.decision is ActionDecision.BLOCK
    assert "scope" in recipient_result.reason


def test_limits_block_repeated_requests(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[1]
    database_path = tmp_path / "records.db"
    outbox_path = tmp_path / "outbox.db"
    initialize_demo_databases(database_path, outbox_path)
    gateway = ActionGateway(
        ControlledTools(
            project_root / "sample_data" / "documents", database_path, outbox_path
        ),
        GatewayPolicy(max_tool_calls_per_task=2, max_calls_per_tool=1),
    )
    first = gateway.handle(
        {
            "task_id": "limited-task",
            "tool_name": "search_approved_documents",
            "arguments": {"query": "security"},
        }
    )
    repeated = gateway.handle(
        {
            "task_id": "limited-task",
            "tool_name": "search_approved_documents",
            "arguments": {"query": "security"},
        }
    )

    assert first.decision is ActionDecision.ALLOW
    assert repeated.decision is ActionDecision.BLOCK
    assert "Repeated" in repeated.reason
