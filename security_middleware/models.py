"""Validated data structures shared by the model client and agent loop."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class FunctionCall(BaseModel):
    """A model-proposed function name and its structured arguments."""

    name: str = Field(min_length=1)
    arguments: dict[str, Any] = Field(default_factory=dict)


class ToolCall(BaseModel):
    """A request to invoke one declared function."""

    type: Literal["function"] = "function"
    function: FunctionCall


class ChatMessage(BaseModel):
    """One message exchanged with Ollama's chat API."""

    role: Literal["user", "assistant", "tool"]
    content: str = ""
    tool_name: str | None = None
    tool_calls: list[ToolCall] = Field(default_factory=list)


class AgentResult(BaseModel):
    """The bounded loop's final outcome."""

    final_response: str
    tool_calls_used: int
    reached_iteration_limit: bool
