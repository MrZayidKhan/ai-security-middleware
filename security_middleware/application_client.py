"""Application-side client for the limited middleware API, with no bypass fallback."""
import json
from urllib.error import HTTPError,URLError
from urllib.request import Request,urlopen

from .models import ChatMessage
from .middleware import ModelContextBlockedError
from .ollama_client import ModelConnectionError,ModelResponseError


class MiddlewareChatClient:
    """Use for answering requests only. Classifiers must still call Ollama directly."""
    def __init__(self,base_url='http://127.0.0.1:8787',timeout_seconds=240):
        self._url=base_url.rstrip('/')+'/api/chat'
        self._timeout=timeout_seconds

    def chat(self,messages:list[ChatMessage],tools:list[dict[str,object]])->ChatMessage:
        if tools or any(message.tool_calls or message.tool_name for message in messages):
            raise ValueError('The middleware client supports tool-free text requests only')
        payload=dict(model='qwen3.5:4b',stream=False,
                     messages=[dict(role=m.role,content=m.content) for m in messages])
        request=Request(self._url,data=json.dumps(payload).encode('utf-8'),
                        headers={'Content-Type':'application/json'},method='POST')
        try:
            with urlopen(request,timeout=self._timeout) as response:
                body=json.load(response)
        except HTTPError as error:
            if error.code==403:
                raise ModelContextBlockedError('Middleware withheld this request (HTTP 403).') from error
            raise ModelConnectionError(f'Middleware request failed (HTTP {error.code}); no direct-model fallback.') from error
        except (URLError,TimeoutError) as error:
            raise ModelConnectionError('Middleware unavailable; no direct-model fallback.') from error
        except (ValueError,UnicodeError) as error:
            raise ModelResponseError('Middleware returned invalid JSON.') from error
        try:
            if body.get('done') is not True or body.get('middleware',{}).get('decision')!='RELEASED':
                raise ValueError('Missing release receipt')
            reply=ChatMessage.model_validate(body['message'])
            if reply.role!='assistant' or reply.tool_calls:
                raise ValueError('Unsupported middleware response')
            return reply
        except Exception as error:
            raise ModelResponseError('Middleware returned an invalid release receipt or message.') from error
