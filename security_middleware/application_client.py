"""Application-side client for the limited middleware API, with no bypass fallback."""
import json
from urllib.error import HTTPError,URLError
from urllib.request import Request,urlopen

from .models import ChatMessage
from .middleware import ModelContextBlockedError
from .ollama_client import ModelConnectionError,ModelResponseError


class MiddlewareChatClient:
    """Use for answering requests only. Classifiers must still call Ollama directly."""
    def __init__(self,base_url='http://127.0.0.1:8787',timeout_seconds=240, *, model='qwen3.5:4b'):
        self._base_url=base_url.rstrip('/')
        self._timeout=timeout_seconds
        self._model=model

    def chat(self,messages:list[ChatMessage],tools:list[dict[str,object]])->ChatMessage:
        body = self._post('/api/chat', messages, tools)
        try:
            if body.get('done') is not True or body.get('middleware',{}).get('decision')!='RELEASED':
                raise ValueError('Missing release receipt')
            reply=ChatMessage.model_validate(body['message'])
            if reply.role!='assistant' or reply.tool_calls:
                raise ValueError('Unsupported middleware response')
            return reply
        except Exception as error:
            raise ModelResponseError('Middleware returned an invalid release receipt or message.') from error

    def screen(self, message: ChatMessage) -> list[str]:
        body = self._post('/api/demo/screen', [message], [])
        try:
            receipt = body['middleware']
            decisions = receipt['content_decisions']
            if body['model_called'] is not False or receipt['decision'] != 'RELEASED' or not isinstance(decisions, list):
                raise ValueError('Invalid screening receipt')
            return decisions
        except (KeyError, TypeError, ValueError) as error:
            raise ModelResponseError('Middleware returned an invalid screening receipt.') from error

    def _post(self, path, messages, tools):
        if tools or any(message.tool_calls or message.tool_name for message in messages):
            raise ValueError('The middleware client supports tool-free text requests only')
        payload=dict(model=self._model,stream=False,
                     messages=[dict(role=m.role,content=m.content) for m in messages])
        request=Request(self._base_url+path,data=json.dumps(payload).encode('utf-8'),
                        headers={'Content-Type':'application/json'},method='POST')
        try:
            with urlopen(request,timeout=self._timeout) as response:
                return json.load(response)
        except HTTPError as error:
            if error.code==403:
                raise ModelContextBlockedError('Middleware withheld this request (HTTP 403).') from error
            raise ModelConnectionError(f'Middleware request failed (HTTP {error.code}); no direct-model fallback.') from error
        except (URLError,TimeoutError) as error:
            raise ModelConnectionError('Middleware unavailable; no direct-model fallback.') from error
        except (ValueError,UnicodeError) as error:
            raise ModelResponseError('Middleware returned invalid JSON.') from error
