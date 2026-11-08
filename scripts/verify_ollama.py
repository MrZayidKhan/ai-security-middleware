"""Verify that the selected local Ollama model responds and proposes a tool call."""

from __future__ import annotations

import json
from urllib.error import URLError
from urllib.request import Request, urlopen


MODEL_NAME = "qwen3.5:4b"
OLLAMA_CHAT_URL = "http://127.0.0.1:11434/api/chat"


def send_chat_request(payload: dict[str, object]) -> dict[str, object]:
    """Send one non-streaming chat request to the local Ollama API."""
    request = Request(
        OLLAMA_CHAT_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=90) as response:
        return json.loads(response.read().decode("utf-8"))


def main() -> None:
    """Run a plain response check followed by a structured tool-call check."""
    try:
        plain_response = send_chat_request(
            {
                "model": MODEL_NAME,
                "stream": False,
                "think": False,
                "messages": [
                    {"role": "user", "content": "Reply with exactly: LOCAL_MODEL_OK"}
                ],
            }
        )
        plain_text = plain_response["message"]["content"]
        print(f"Plain response: {plain_text}")

        tool_response = send_chat_request(
            {
                "model": MODEL_NAME,
                "stream": False,
                "think": False,
                "messages": [
                    {
                        "role": "user",
                        "content": (
                            "Use the supplied get_document tool to request the document "
                            "with document_id project-overview."
                        ),
                    }
                ],
                "tools": [
                    {
                        "type": "function",
                        "function": {
                            "name": "get_document",
                            "description": "Read an approved document by its document ID.",
                            "parameters": {
                                "type": "object",
                                "required": ["document_id"],
                                "properties": {
                                    "document_id": {
                                        "type": "string",
                                        "description": "The approved document ID to read.",
                                    }
                                },
                            },
                        },
                    }
                ],
            }
        )
    except (URLError, TimeoutError) as error:
        raise SystemExit(f"Could not reach local Ollama: {error}") from error

    tool_calls = tool_response["message"].get("tool_calls", [])
    if not tool_calls:
        raise SystemExit("The model did not return a tool call.")

    tool_call = tool_calls[0]["function"]
    print(
        "Tool proposal: "
        f"{tool_call['name']}({json.dumps(tool_call['arguments'], sort_keys=True)})"
    )

    if tool_call["name"] != "get_document":
        raise SystemExit("The model proposed an unexpected tool.")
    if tool_call["arguments"].get("document_id") != "project-overview":
        raise SystemExit("The model proposed an unexpected document ID.")

    print("Local model and structured tool-call checks passed.")


if __name__ == "__main__":
    main()
