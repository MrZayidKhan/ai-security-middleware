"""Small client for the local Ollama chat endpoint."""

from __future__ import annotations

import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from pydantic import ValidationError

from security_middleware.models import ChatMessage


class ModelConnectionError(RuntimeError):
    """Raised when the local Ollama service cannot be reached."""


class ModelResponseError(RuntimeError):
    """Raised when Ollama returns data that is not a valid chat message."""


class OllamaClient:
    """Send non-streaming chat requests to a chosen local Ollama model."""

    def __init__(
        self,
        model_name: str = "qwen3.5:4b",
        base_url: str = "http://127.0.0.1:11434",
        timeout_seconds: int = 90,
    ) -> None:
        self._model_name = model_name
        self._chat_url = f"{base_url.rstrip('/')}/api/chat"
        self._timeout_seconds = timeout_seconds

    def chat(
        self, messages: list[ChatMessage], tools: list[dict[str, object]]
    ) -> ChatMessage:
        """Return the next validated assistant message from the local model."""
        payload = {
            "model": self._model_name,
            "stream": False,
            "think": False,
            "messages": [message.model_dump(exclude_none=True) for message in messages],
            "tools": tools,
        }
        request = Request(
            self._chat_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urlopen(request, timeout=self._timeout_seconds) as response:
                raw_response: dict[str, Any] = json.loads(
                    response.read().decode("utf-8")
                )
        except (HTTPError, URLError, TimeoutError) as error:
            raise ModelConnectionError(f"Could not reach local Ollama: {error}") from error
        except json.JSONDecodeError as error:
            raise ModelResponseError("Ollama returned invalid JSON.") from error

        return self.parse_response(raw_response)

    @staticmethod
    def parse_response(raw_response: dict[str, Any]) -> ChatMessage:
        """Validate the message field returned by Ollama."""
        try:
            return ChatMessage.model_validate(raw_response["message"])
        except (KeyError, ValidationError) as error:
            raise ModelResponseError("Ollama returned an invalid chat message.") from error
