"""Tool-free local model demonstration with a verifiable forwarding receipt."""
from hashlib import sha256
from typing import Protocol
from uuid import uuid4

from pydantic import BaseModel

from security_middleware.content_protection import ContentInspector, ContentDecision
from security_middleware.middleware import PromptSecurityMiddleware, ModelContextDecision
from security_middleware.review_queue import ReviewQueue
from security_middleware.models import ChatMessage


class ChatClient(Protocol):
    def chat(self, messages: list[ChatMessage], tools: list[dict[str, object]]) -> ChatMessage: ...


class ForwardingReceipt(BaseModel):
    request_id: str
    decision: str
    content_decisions: list[str]
    model_called: bool = False
    forwarded_characters: int = 0
    forwarded_sha256: str | None = None
    reason: str
    response: str | None = None
    error: str | None = None
    review_id: int | None = None
    source_id: str | None = None
    content_id: str | None = None
    data_sensitivity: str | None = None


def run_protected_demo(task: str, context: str, inspector: ContentInspector, client: ChatClient) -> ForwardingReceipt:
    """Withhold the entire request if task or retrieved context requires review.

    This flow offers no tools. Context labels aid interpretation; the model is
    still vulnerable to undetected instructions and hashing is evidence, not a
    safety mechanism.
    """
    messages = [ChatMessage(role='user', content=task)]
    if context:
        messages.append(ChatMessage(role='user', content='Retrieved untrusted context:\n' + context))
    screened = PromptSecurityMiddleware(inspector).before_model(messages,
        retrieved_message_indices=frozenset({1}) if context else frozenset())
    receipt = ForwardingReceipt(request_id=str(uuid4()), decision=screened.decision.value,
        content_decisions=[item.value for item in screened.content_decisions], reason=screened.reason)
    if screened.decision is ModelContextDecision.BLOCKED:
        return receipt
    return _forward(screened.messages, receipt, client)


def run_reviewed_demo(task: str, review_id: int, queue: ReviewQueue,
                      inspector: ContentInspector, client: ChatClient) -> ForwardingReceipt:
    """Explicitly continue with one approved excerpt, rechecking its provenance.

    Invalid reviews raise before any detector or answering-model call. Approval
    is not a detector bypass; a changed policy may still withhold an excerpt.
    """
    approved = queue.approved_content(review_id)
    receipt = ForwardingReceipt(request_id=str(uuid4()), decision='BLOCKED',
        content_decisions=[], reason='Review continuation withheld.', review_id=review_id,
        source_id=approved.source_id, content_id=approved.content_id,
        data_sensitivity=approved.data_sensitivity.value)
    screened_task = PromptSecurityMiddleware(inspector).before_model_text(task)
    receipt.content_decisions = [item.value for item in screened_task.content_decisions]
    if screened_task.decision is ModelContextDecision.BLOCKED:
        receipt.reason = screened_task.reason
        return receipt
    inspected = inspector.inspect(approved.model_copy(update={'trusted_task':task}))
    receipt.content_decisions.append(inspected.decision.value)
    if inspected.decision is ContentDecision.HOLD_FOR_REVIEW or inspected.sanitized_content is None:
        receipt.reason = inspected.reason
        return receipt
    messages = screened_task.messages + [ChatMessage(role='user',
        content='Reviewed excerpt (still untrusted):\n' + inspected.sanitized_content)]
    receipt.decision = 'RELEASED'
    receipt.reason = 'Task and approved excerpt passed the current inspection policy.'
    return _forward(messages, receipt, client)


def _forward(forwarded: list[ChatMessage], receipt: ForwardingReceipt,
             client: ChatClient) -> ForwardingReceipt:
    # Hash the exact structured message payload, not a potentially ambiguous join.
    payload = '[' + ','.join(message.model_dump_json() for message in forwarded) + ']'
    receipt.forwarded_sha256 = sha256(payload.encode('utf-8')).hexdigest()
    receipt.forwarded_characters = sum(len(message.content) for message in forwarded)
    receipt.model_called = True
    try:
        reply = client.chat(forwarded, tools=[])
        if reply.role != 'assistant' or reply.tool_calls:
            raise ValueError('This demonstration accepts only tool-free assistant text.')
        receipt.response = reply.content
    except Exception as error:
        receipt.error = f'Model request failed ({type(error).__name__}).'
    return receipt
