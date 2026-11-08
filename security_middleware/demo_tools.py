"""The single harmless tool used to demonstrate the initial agent loop."""

from __future__ import annotations

from pydantic import BaseModel

from security_middleware.models import ToolCall


class ToolExecutionResult(BaseModel):
    """A controlled tool result sent back to the model."""

    content: str
    executed: bool


def get_project_status() -> str:
    """Return fixed demonstration text without reading any local resource."""
    return "The project is running the initial agent-loop demonstration milestone."


def project_status_tool_definition() -> dict[str, object]:
    """Describe the fixed tool in the format expected by Ollama."""
    return {
        "type": "function",
        "function": {
            "name": "get_project_status",
            "description": "Get the current status of this demonstration project.",
            "parameters": {"type": "object", "properties": {}},
        },
    }


class DemoToolExecutor:
    """Dispatch only the one harmless tool used in this milestone."""

    def execute(self, tool_call: ToolCall) -> ToolExecutionResult:
        """Return a result without allowing arbitrary function execution."""
        if tool_call.function.name != "get_project_status":
            return ToolExecutionResult(
                content="This demonstration does not provide that tool.", executed=False
            )

        if tool_call.function.arguments:
            return ToolExecutionResult(
                content="get_project_status does not accept arguments.", executed=False
            )

        return ToolExecutionResult(content=get_project_status(), executed=True)
