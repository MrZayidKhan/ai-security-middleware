"""Run the initial local agent-loop demonstration."""

from security_middleware.agent_loop import AgentLoop
from security_middleware.ollama_client import OllamaClient


def main() -> None:
    """Ask the local model to use the harmless project-status tool."""
    agent = AgentLoop(OllamaClient())
    result = agent.run(
        "Use get_project_status, then give a short answer about the project status."
    )
    print(f"Tool calls used: {result.tool_calls_used}")
    print(f"Final response: {result.final_response}")

    if result.reached_iteration_limit:
        raise SystemExit("The demonstration reached its tool-call limit.")


if __name__ == "__main__":
    main()
