"""End-to-end protected retrieval for approved local documents."""

from __future__ import annotations

from pydantic import BaseModel

from security_middleware.action_gateway import ActionDecision, ActionGateway, GatewayResult
from security_middleware.content_protection import (
    ContentDecision,
    ContentEnvelope,
    ContentInspectionResult,
    ContentInspector,
    DataSensitivity,
    OriginTrust,
)
from security_middleware.review_queue import ReviewQueue


class SecureRetrievalResult(BaseModel):
    action: GatewayResult
    inspection: ContentInspectionResult | None = None
    review_id: int | None = None
    content_for_model: str | None = None


class SecureDocumentRetrieval:
    """Read documents only through the gateway, then inspect returned content."""

    def __init__(
        self,
        gateway: ActionGateway,
        inspector: ContentInspector,
        review_queue: ReviewQueue,
    ) -> None:
        self._gateway = gateway
        self._inspector = inspector
        self._review_queue = review_queue

    def retrieve(self, task_id: str, document_id: str) -> SecureRetrievalResult:
        """Authorize, read, inspect, and conditionally hold one document."""
        action = self._gateway.handle(
            {
                "task_id": task_id,
                "tool_name": "read_approved_document",
                "arguments": {"document_id": document_id},
            }
        )
        if action.decision is not ActionDecision.ALLOW or action.result is None:
            return SecureRetrievalResult(action=action)

        envelope = ContentEnvelope(
            source_id="approved-local-document",
            content_id=document_id,
            origin_trust=OriginTrust.UNTRUSTED,
            data_sensitivity=DataSensitivity.PUBLIC,
            content=action.result["content"],
        )
        inspection = self._inspector.inspect(envelope)
        if inspection.decision is ContentDecision.HOLD_FOR_REVIEW:
            review_item = self._review_queue.create(envelope, inspection)
            return SecureRetrievalResult(
                action=action, inspection=inspection, review_id=review_item.review_id
            )

        return SecureRetrievalResult(
            action=action,
            inspection=inspection,
            content_for_model=inspection.sanitized_content,
        )
