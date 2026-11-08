"""Independent authorization gateway for controlled local tools."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from security_middleware.controlled_tools import (
    APPROVED_RECIPIENTS,
    DOCUMENT_FILES,
    ControlledTools,
    DraftMessageRequest,
    ProjectRecordRequest,
    ReadDocumentRequest,
    SearchDocumentsRequest,
    ToolExecutionError,
)


class ActionDecision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"


class ExecutionOutcome(str, Enum):
    NOT_EXECUTED = "NOT_EXECUTED"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"


class GatewayRequest(BaseModel):
    """A structured proposal received before any local operation is run."""

    model_config = ConfigDict(extra="forbid")

    task_id: str = Field(min_length=1, max_length=64)
    tool_name: str = Field(min_length=1, max_length=64)
    arguments: dict[str, Any] = Field(default_factory=dict)


class GatewayResult(BaseModel):
    """The authorization decision and resulting execution state."""

    request_id: str
    task_id: str | None
    tool_name: str | None
    decision: ActionDecision
    reason: str
    execution_outcome: ExecutionOutcome
    result: Any | None = None


@dataclass(frozen=True)
class GatewayPolicy:
    """Fixed permissions and limits for the initial controlled tools."""

    allowed_tools: frozenset[str] = frozenset(
        {
            "search_approved_documents",
            "read_approved_document",
            "get_project_record",
            "draft_local_message",
        }
    )
    allowed_document_ids: frozenset[str] = frozenset(DOCUMENT_FILES)
    allowed_record_ids: frozenset[int] = frozenset({1, 2})
    allowed_recipients: frozenset[str] = frozenset(APPROVED_RECIPIENTS)
    max_tool_calls_per_task: int = 4
    max_calls_per_tool: int = 2


class ControlledToolExecutor:
    """Dispatch validated calls to fixed application functions only."""

    def __init__(self, tools: ControlledTools) -> None:
        self._tools = tools

    def execute(self, tool_name: str, arguments: BaseModel) -> Any:
        """Execute a known operation after the gateway has authorized it."""
        if tool_name == "search_approved_documents":
            return [
                match.model_dump()
                for match in self._tools.search_documents(arguments.query)  # type: ignore[attr-defined]
            ]
        if tool_name == "read_approved_document":
            return self._tools.read_document(  # type: ignore[attr-defined]
                arguments.document_id
            ).model_dump()
        if tool_name == "get_project_record":
            record = self._tools.get_project_record(arguments.record_id)  # type: ignore[attr-defined]
            return record.model_dump() if record else None
        if tool_name == "draft_local_message":
            return self._tools.draft_message(  # type: ignore[attr-defined]
                arguments.recipient,
                arguments.subject,
                arguments.body,
            ).model_dump()

        raise RuntimeError("The executor received an unrecognized tool.")


class ActionGateway:
    """Authorize controlled-tool proposals before a fixed executor can run them."""

    _argument_models: dict[str, type[BaseModel]] = {
        "search_approved_documents": SearchDocumentsRequest,
        "read_approved_document": ReadDocumentRequest,
        "get_project_record": ProjectRecordRequest,
        "draft_local_message": DraftMessageRequest,
    }

    def __init__(
        self,
        tools: ControlledTools,
        policy: GatewayPolicy | None = None,
    ) -> None:
        self._policy = policy or GatewayPolicy()
        self._executor = ControlledToolExecutor(tools)
        self._calls_per_task: Counter[str] = Counter()
        self._calls_per_tool: dict[str, Counter[str]] = defaultdict(Counter)
        self._decision_history: list[GatewayResult] = []

    @property
    def decision_history(self) -> tuple[GatewayResult, ...]:
        """Expose an immutable view of decisions until persistent audit logging exists."""
        return tuple(self._decision_history)

    def handle(self, raw_request: dict[str, Any]) -> GatewayResult:
        """Validate, authorize, and then optionally execute one tool proposal."""
        request_id = str(uuid4())
        try:
            request = GatewayRequest.model_validate(raw_request)
        except ValidationError:
            return self._record(
                GatewayResult(
                    request_id=request_id,
                    task_id=None,
                    tool_name=None,
                    decision=ActionDecision.BLOCK,
                    reason="Malformed gateway request.",
                    execution_outcome=ExecutionOutcome.NOT_EXECUTED,
                )
            )

        limit_result = self._check_and_count_limits(request, request_id)
        if limit_result:
            return limit_result

        if request.tool_name not in self._policy.allowed_tools:
            return self._block(request, request_id, "Tool is not allowlisted.")

        arguments = self._validate_arguments(request, request_id)
        if isinstance(arguments, GatewayResult):
            return arguments

        scope_reason = self._scope_violation(request.tool_name, arguments)
        if scope_reason:
            return self._block(request, request_id, scope_reason)

        try:
            result = self._executor.execute(request.tool_name, arguments)
        except ToolExecutionError:
            return self._record(
                GatewayResult(
                    request_id=request_id,
                    task_id=request.task_id,
                    tool_name=request.tool_name,
                    decision=ActionDecision.ALLOW,
                    reason="Tool was authorized but local execution failed.",
                    execution_outcome=ExecutionOutcome.FAILED,
                )
            )

        return self._record(
            GatewayResult(
                request_id=request_id,
                task_id=request.task_id,
                tool_name=request.tool_name,
                decision=ActionDecision.ALLOW,
                reason="Tool is allowlisted, valid, and within scope.",
                execution_outcome=ExecutionOutcome.SUCCEEDED,
                result=result,
            )
        )

    def _check_and_count_limits(
        self, request: GatewayRequest, request_id: str
    ) -> GatewayResult | None:
        if self._calls_per_task[request.task_id] >= self._policy.max_tool_calls_per_task:
            return self._block(request, request_id, "Task tool-call limit reached.")
        if (
            self._calls_per_tool[request.task_id][request.tool_name]
            >= self._policy.max_calls_per_tool
        ):
            return self._block(request, request_id, "Repeated tool-call limit reached.")

        self._calls_per_task[request.task_id] += 1
        self._calls_per_tool[request.task_id][request.tool_name] += 1
        return None

    def _validate_arguments(
        self, request: GatewayRequest, request_id: str
    ) -> BaseModel | GatewayResult:
        model = self._argument_models.get(request.tool_name)
        if model is None:
            return self._block(request, request_id, "Tool has no argument contract.")

        try:
            return model.model_validate(request.arguments)
        except ValidationError:
            return self._block(request, request_id, "Tool arguments are invalid.")

    def _scope_violation(self, tool_name: str, arguments: BaseModel) -> str | None:
        if tool_name == "read_approved_document":
            if arguments.document_id not in self._policy.allowed_document_ids:  # type: ignore[attr-defined]
                return "Document is outside the permitted scope."
        elif tool_name == "get_project_record":
            if arguments.record_id not in self._policy.allowed_record_ids:  # type: ignore[attr-defined]
                return "Record is outside the permitted scope."
        elif tool_name == "draft_local_message":
            if arguments.recipient not in self._policy.allowed_recipients:  # type: ignore[attr-defined]
                return "Recipient is outside the permitted scope."
        return None

    def _block(
        self, request: GatewayRequest, request_id: str, reason: str
    ) -> GatewayResult:
        return self._record(
            GatewayResult(
                request_id=request_id,
                task_id=request.task_id,
                tool_name=request.tool_name,
                decision=ActionDecision.BLOCK,
                reason=reason,
                execution_outcome=ExecutionOutcome.NOT_EXECUTED,
            )
        )

    def _record(self, result: GatewayResult) -> GatewayResult:
        """Retain each decision until the persistent audit log is added."""
        self._decision_history.append(result)
        return result
