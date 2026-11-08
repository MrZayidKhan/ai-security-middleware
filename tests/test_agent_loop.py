"""Tests for the bounded initial tool-calling loop."""

from __future__ import annotations

import pytest

from security_middleware.agent_loop import AgentLoop
from security_middleware.models import ChatMessage, FunctionCall, ToolCall
from security_middleware.ollama_client import ModelResponseError, OllamaClient


class FakeClient:
    """Return prepared responses while recording the conversation passed to it."""

    def __init__(self, replies: list[ChatMessage]) -> None:
        self._replies = replies
        self.messages_by_call: list[list[ChatMessage]] = []

    def chat(
        self, messages: list[ChatMessage], tools: list[dict[str, object]]
    ) -> ChatMessage:
        self.messages_by_call.append(list(messages))
        return self._replies.pop(0)


def project_status_call() -> ToolCall:
    """Build the one allowed demonstration proposal."""
    return ToolCall(function=FunctionCall(name="get_project_status"))


def test_loop_returns_final_response_after_harmless_tool() -> None:
    client = FakeClient(
        [
            ChatMessage(role="assistant", tool_calls=[project_status_call()]),
            ChatMessage(role="assistant", content="The project status was returned."),
        ]
    )

    result = AgentLoop(client).run("What is the project status?")

    assert result.final_response == "The project status was returned."
    assert result.tool_calls_used == 1
    assert not result.reached_iteration_limit
    assert client.messages_by_call[1][-1].role == "tool"
    assert "initial agent-loop" in client.messages_by_call[1][-1].content


def test_loop_stops_after_the_configured_limit() -> None:
    client = FakeClient(
        [ChatMessage(role="assistant", tool_calls=[project_status_call()]) for _ in range(2)]
    )

    result = AgentLoop(client, max_tool_rounds=2).run("Keep checking status.")

    assert result.reached_iteration_limit
    assert result.tool_calls_used == 2


def test_invalid_model_message_is_rejected() -> None:
    raw_response = {
        "message": {
            "role": "assistant",
            "tool_calls": [{"type": "function", "function": {"arguments": {}}}],
        }
    }

    with pytest.raises(ModelResponseError):
        OllamaClient.parse_response(raw_response)


def test_loop_requires_a_positive_limit() -> None:
    with pytest.raises(ValueError, match="at least 1"):
        AgentLoop(FakeClient([]), max_tool_rounds=0)
