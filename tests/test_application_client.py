import io
import json
from urllib.error import HTTPError
import pytest
from security_middleware.application_client import MiddlewareChatClient
from security_middleware.models import ChatMessage
from security_middleware.middleware import ModelContextBlockedError
from security_middleware.ollama_client import ModelConnectionError,ModelResponseError


def test_client_sends_only_supported_gateway_fields(monkeypatch):
    def open_request(request,timeout):
        body=json.loads(request.data)
        assert set(body)=={'model','messages','stream'}
        assert body['messages']==[{'role':'user','content':'Hello'}]
        assert request.full_url=='http://127.0.0.1:8787/api/chat'
        return io.BytesIO(json.dumps({'done':True,'middleware':{'decision':'RELEASED'},
                                     'message':{'role':'assistant','content':'Reply'}}).encode())
    monkeypatch.setattr('security_middleware.application_client.urlopen',open_request)
    assert MiddlewareChatClient().chat([ChatMessage(role='user',content='Hello')],[]).content=='Reply'


@pytest.mark.parametrize('status,error_type',[(403,ModelContextBlockedError),(503,ModelConnectionError),(429,ModelConnectionError)])
def test_http_errors_never_fall_back(monkeypatch,status,error_type):
    calls=[]
    def unavailable(request,timeout):
        calls.append(request.full_url)
        raise HTTPError(request.full_url,status,'error',{},None)
    monkeypatch.setattr('security_middleware.application_client.urlopen',unavailable)
    with pytest.raises(error_type):MiddlewareChatClient().chat([ChatMessage(role='user',content='Hello')],[])
    assert calls==['http://127.0.0.1:8787/api/chat']


def test_missing_release_receipt_rejected(monkeypatch):
    monkeypatch.setattr('security_middleware.application_client.urlopen',lambda *a,**k:io.BytesIO(b'{"message":{"role":"assistant","content":"unverified"}}'))
    with pytest.raises(ModelResponseError):MiddlewareChatClient().chat([ChatMessage(role='user',content='Hi')],[])


def test_supplied_tools_are_not_silently_dropped():
    with pytest.raises(ValueError):MiddlewareChatClient().chat([], [{'function':{'name':'arbitrary'}}])
