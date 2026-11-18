import json
from unittest.mock import patch

from security_middleware.content_assessor import OllamaContentAssessor, ModelAssessment, AssessmentUnavailableError
from security_middleware.models import ChatMessage
import pytest


def test_assessor_requests_constrained_json_without_tools():
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self):
            return json.dumps({'message': {'role': 'assistant', 'content': json.dumps({
                'risk': 'benign', 'reason': 'Normal request', 'suspicious_spans': []})}}).encode()
    with patch('security_middleware.ollama_client.urlopen', return_value=Response()) as send:
        assert OllamaContentAssessor().assess('Hello.').risk == 'benign'
    body = json.loads(send.call_args.args[0].data)
    assert body['format'] == ModelAssessment.model_json_schema()
    assert body['options']['temperature'] == 0
    assert body['tools'] == []


def test_invalid_assessment_is_not_accepted_as_benign():
    class Client:
        def chat(self, messages, tools):
            return ChatMessage(role='assistant', content='not valid JSON')
    with pytest.raises(AssessmentUnavailableError):
        OllamaContentAssessor(Client()).assess('Hello.')
