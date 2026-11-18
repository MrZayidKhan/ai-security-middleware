"""Loopback model gateway: inspect before forwarding to local Ollama."""
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from threading import BoundedSemaphore
from uuid import uuid4
import json

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, ConfigDict, Field, model_validator

from security_middleware.audit_log import AuditLog, initialize_audit_database
from security_middleware.content_assessor import OllamaContentAssessor
from security_middleware.content_protection import ContentInspector
from security_middleware.middleware import PromptSecurityMiddleware, ModelContextDecision
from security_middleware.models import ChatMessage
from security_middleware.ollama_client import OllamaClient, ModelConnectionError, ModelResponseError


class InputMessage(BaseModel):
    model_config = ConfigDict(extra='forbid')
    role: str
    content: str = Field(min_length=1, max_length=20000)

    @model_validator(mode='after')
    def allowed_role(self):
        if self.role not in {'user', 'assistant', 'tool'}:
            raise ValueError('Only user, assistant and tool text messages are supported.')
        return self


class ChatRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    model: str = 'qwen3.5:4b'
    messages: list[InputMessage] = Field(min_length=1, max_length=32)
    stream: bool = False

    @model_validator(mode='after')
    def bounded_request(self):
        if self.stream:
            raise ValueError('Streaming is not supported by this gateway.')
        if sum(len(message.content) for message in self.messages) > 40000:
            raise ValueError('Combined context exceeds 40000 characters.')
        if not any(message.role == 'user' for message in self.messages):
            raise ValueError('At least one user message is required.')
        return self


def create_app(inspector=None, client=None, audit=None) -> FastAPI:
    app = FastAPI(title='Local prompt security middleware', version='0.1.0')
    scanner = inspector or ContentInspector(assessor=OllamaContentAssessor(),
                                          require_assessment_for_untrusted=True)
    model_client = client or OllamaClient()
    # HTTP caller controls every role: even claimed assistant history is untrusted.
    boundary = PromptSecurityMiddleware(scanner, inspect_roles=frozenset({'user', 'tool', 'assistant'}))
    capacity = BoundedSemaphore(1)
    if audit is None:
        path = Path(__file__).resolve().parents[1]/'runtime_data'/'security_events.db'
        initialize_audit_database(path)
        audit = AuditLog(path)

    @app.middleware('http')
    async def local_requests_only(request: Request, call_next):
        # No cross-origin browser calls; extensions need an explicit integration.
        if request.headers.get('origin'):
            return JSONResponse(status_code=403, content={'error': 'Browser-origin calls are not enabled.'})
        if request.client and request.client.host not in {'127.0.0.1', '::1', 'testclient'}:
            return JSONResponse(status_code=403, content={'error': 'Loopback access only.'})
        # Bound body before Pydantic parsing, including chunked transfer bodies.
        size = 0
        body = []
        async for chunk in request.stream():
            size += len(chunk)
            if size > 256000:
                return JSONResponse(status_code=413, content={'error': 'Request body too large.'})
            body.append(chunk)
        request._body = b''.join(body)
        # `call_next` receives the ASGI stream, not the private `_body` cache.
        # Replay the bounded body after inspection so FastAPI can parse it.
        async def replay_body():
            return {'type': 'http.request', 'body': request._body, 'more_body': False}
        request._receive = replay_body
        return await call_next(request)

    @app.exception_handler(Exception)
    async def safe_failure(request, error):
        return JSONResponse(status_code=503, content={'error': 'Middleware request failed. Do not assume completion; inspect the local event log.'})

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request, error):
        # Do not echo potentially sensitive rejected request bodies.
        return JSONResponse(status_code=422, content={'error': 'invalid_request',
            'fields': [list(item['loc']) for item in error.errors()]})

    @app.get('/health')
    def health():
        return {'service': 'prompt-security-middleware', 'status': 'running',
                'detectors': 'rules+required-local-qwen', 'upstream_checked': False}

    @app.post('/api/chat')
    def chat(payload: ChatRequest):
        if payload.model != 'qwen3.5:4b':
            raise HTTPException(422, 'Model is not configured for this local gateway.')
        if not capacity.acquire(blocking=False):
            raise HTTPException(429, 'Middleware busy; retry later.')
        request_id = str(uuid4())
        try:
            messages = [ChatMessage(role=message.role, content=message.content) for message in payload.messages]
            screened = boundary.before_model(messages)
            decisions = [decision.value for decision in screened.content_decisions]
            audit.record('middleware_inspection', 'Model context screened.',
                         {'request_id': request_id, 'content_decisions': decisions}, decision=screened.decision.value)
            if screened.decision is ModelContextDecision.BLOCKED:
                unavailable = 'unavailable' in screened.reason.lower() or 'not configured' in screened.reason.lower()
                return JSONResponse(status_code=503 if unavailable else 403, content={
                    'error': 'detector_unavailable' if unavailable else 'content_withheld',
                    'request_id': request_id, 'reason': screened.reason, 'model_called': False,
                    'content_decisions': decisions})
            forwarded = screened.messages
            digest = sha256(json.dumps([m.model_dump() for m in forwarded], sort_keys=True).encode()).hexdigest()
            # Persist authorization before the upstream side effect; failure stops forwarding.
            audit.record('middleware_forward', 'Inspected context authorized for forwarding.',
                         {'request_id': request_id, 'forwarded_sha256': digest}, decision='RELEASED')
            try:
                response = model_client.chat(forwarded, tools=[])
                if response.role != 'assistant' or response.tool_calls:
                    raise ModelResponseError('Unexpected response shape.')
            except (ModelConnectionError, ModelResponseError):
                audit.record('middleware_outcome', 'Upstream request failed.',
                             {'request_id': request_id}, decision='FAILED')
                return JSONResponse(status_code=502, content={'error': 'upstream_failed', 'request_id': request_id,
                                                              'model_called': True})
            audit.record('middleware_outcome', 'Upstream response received.',
                         {'request_id': request_id}, decision='SUCCEEDED')
            return {'model': payload.model, 'created_at': datetime.now(timezone.utc).isoformat(),
                    'message': response.model_dump(exclude_none=True), 'done': True,
                    'middleware': {'request_id': request_id, 'decision': 'RELEASED',
                                   'content_decisions': decisions, 'forwarded_sha256': digest}}
        finally:
            capacity.release()

    return app
