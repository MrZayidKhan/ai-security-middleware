"""Model-facing security boundary for untrusted prompts and tool results."""

from __future__ import annotations

from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, Field

from security_middleware.content_protection import (
    ContentDecision,
    ContentEnvelope,
    ContentInspector,
    DataSensitivity,
    OriginTrust,
)
from security_middleware.models import ChatMessage


class ModelContextBlockedError(RuntimeError):
    """Raised when the middleware refuses to call the model."""


class ModelContextDecision(str, Enum):
    RELEASED = "RELEASED"
    BLOCKED = "BLOCKED"


class ScreenedContext(BaseModel):
    """What the model is allowed to receive after inspection."""

    decision: ModelContextDecision
    messages: list[ChatMessage] | None = None
    content_decisions: list[ContentDecision] = Field(default_factory=list)
    held_content_ids: list[str] = Field(default_factory=list)
    reason: str


class PromptSecurityMiddleware:
    """Screen model-bound context without granting or executing tool authority.

    User and tool messages are treated as untrusted by default. A HOLD removes
    the complete model context; no caller receives a partial or raw held message.
    """

    def __init__(
        self,
        inspector: ContentInspector,
        *,
        inspect_roles: frozenset[str] = frozenset({"user", "tool"}),
    ) -> None:
        invalid = inspect_roles - {"user", "assistant", "tool"}
        if invalid:
            raise ValueError(f"Unsupported message roles: {sorted(invalid)}")
        self._inspector = inspector
        self._inspect_roles = inspect_roles

    def before_model(self, messages: list[ChatMessage], *, retrieved_message_indices: frozenset[int] = frozenset()) -> ScreenedContext:
        """Inspect every configured message and return a safe model context."""
        released: list[ChatMessage] = []
        decisions: list[ContentDecision] = []
        held_ids: list[str] = []
        current_task: str | None = None
        if any(index<0 or index>=len(messages) for index in retrieved_message_indices):
            raise ValueError('Retrieved-message index outside context')

        for index,message in enumerate(messages):
            is_data=message.role!='user' or index in retrieved_message_indices
            if not is_data:
                current_task=message.content
            if message.role not in self._inspect_roles:
                released.append(message.model_copy(deep=True))
                continue
            content_id = str(uuid4())
            result = self._inspector.inspect(
                ContentEnvelope(
                    source_id=f"model-context:{message.role}",
                    content_id=content_id,
                    origin_trust=OriginTrust.UNTRUSTED,
                    data_sensitivity=DataSensitivity.PUBLIC,
                    content=message.content,
                    trusted_task=current_task if is_data and current_task is not None and len(current_task)<=4000 else None,
                    input_channel='retrieved_data' if is_data else 'direct_user',
                )
            )
            decisions.append(result.decision)
            if result.decision is ContentDecision.HOLD_FOR_REVIEW:
                held_ids.append(content_id)
                return ScreenedContext(
                    decision=ModelContextDecision.BLOCKED,
                    content_decisions=decisions,
                    held_content_ids=held_ids,
                    reason=f"Model context withheld ({message.role}): {result.reason}",
                )
            released.append(
                message.model_copy(
                    update={"content": result.sanitized_content if result.sanitized_content is not None else ''},
                    deep=True,
                )
            )

        return ScreenedContext(
            decision=ModelContextDecision.RELEASED,
            messages=released,
            content_decisions=decisions,
            reason="All configured model-bound content passed or was sanitized.",
        )

    def before_model_text(
        self,
        content: str,
        *,
        source_id: str = "model-input",
        data_sensitivity: DataSensitivity = DataSensitivity.PUBLIC,
        trusted_task: str | None = None,
    ) -> ScreenedContext:
        """Convenience entry point for one user or retrieved text payload."""
        result = self._inspector.inspect(
            ContentEnvelope(
                source_id=source_id,
                content_id=str(uuid4()),
                origin_trust=OriginTrust.UNTRUSTED,
                data_sensitivity=data_sensitivity,
                content=content,
                trusted_task=trusted_task,
                input_channel='retrieved_data' if trusted_task is not None else 'direct_user',
            )
        )
        if result.decision is ContentDecision.HOLD_FOR_REVIEW:
            return ScreenedContext(
                decision=ModelContextDecision.BLOCKED,
                content_decisions=[result.decision],
                reason=result.reason,
            )
        return ScreenedContext(
            decision=ModelContextDecision.RELEASED,
            messages=[ChatMessage(role="user", content=result.sanitized_content if result.sanitized_content is not None else '')],
            content_decisions=[result.decision],
            reason=result.reason,
        )


class SecureChatClient:
    """Adapter that places the middleware immediately before a model client."""

    def __init__(self, client, middleware: PromptSecurityMiddleware) -> None:
        self._client = client
        self._middleware = middleware

    def chat(self, messages: list[ChatMessage], tools: list[dict[str, object]]):
        screened = self._middleware.before_model(messages)
        if screened.decision is ModelContextDecision.BLOCKED or screened.messages is None:
            raise ModelContextBlockedError(screened.reason)
        return self._client.chat(screened.messages, tools)
