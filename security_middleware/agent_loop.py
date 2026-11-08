"""Bounded tool-calling loop for the initial local-model demonstration."""

from __future__ import annotations

from typing import Protocol

from security_middleware.demo_tools import DemoToolExecutor, project_status_tool_definition
from security_middleware.models import AgentResult, ChatMessage


class ChatClient(Protocol):
    """The small interface the loop needs from a model client."""

    def chat(
        self, messages: list[ChatMessage], tools: list[dict[str, object]]
    ) -> ChatMessage:
        """Return one assistant response for the supplied conversation."""


class AgentLoop:
    """Ask the model for proposals and return after a bounded number of tool rounds."""

    def __init__(self, client: ChatClient, max_tool_rounds: int = 3) -> None:
        if max_tool_rounds < 1:
            raise ValueError("max_tool_rounds must be at least 1.")

        self._client = client
        self._max_tool_rounds = max_tool_rounds
        self._executor = DemoToolExecutor()
        self._tools = [project_status_tool_definition()]

    def run(self, user_task: str) -> AgentResult:
        """Run the conversation until a final response or the configured limit."""
        messages = [ChatMessage(role="user", content=user_task)]
        tool_calls_used = 0

        for _ in range(self._max_tool_rounds):
            assistant_message = self._client.chat(messages, self._tools)
            messages.append(assistant_message)

            if not assistant_message.tool_calls:
                return AgentResult(
                    final_response=assistant_message.content,
                    tool_calls_used=tool_calls_used,
                    reached_iteration_limit=False,
                )

            for tool_call in assistant_message.tool_calls:
                result = self._executor.execute(tool_call)
                tool_calls_used += 1
                messages.append(
                    ChatMessage(
                        role="tool",
                        tool_name=tool_call.function.name,
                        content=result.content,
                    )
                )

        return AgentResult(
            final_response=(
                "The request stopped because the demonstration reached its tool-call limit."
            ),
            tool_calls_used=tool_calls_used,
            reached_iteration_limit=True,
        )
