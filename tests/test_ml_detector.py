from pathlib import Path

from security_middleware.ml_detector import MLDetector, DetectorOutput
from security_middleware.content_protection import ContentInspector, ContentEnvelope, ContentDecision


def test_missing_model_fails_closed(tmp_path):
    detector = MLDetector(tmp_path / 'missing.joblib')
    result = ContentInspector(detector=detector).inspect(ContentEnvelope(
        source_id='test', content_id='test', origin_trust='untrusted', data_sensitivity='public', content='The report is ready.'))
    assert result.decision == ContentDecision.HOLD_FOR_REVIEW
    assert result.sanitized_content is None
    assert result.detector_outputs[0].risk == 'unavailable'


def test_invalid_artifact_is_unavailable(tmp_path):
    path = tmp_path / 'bad.joblib'
    path.write_bytes(b'not a trained artifact')
    assert MLDetector(path).detect('Hello').risk == 'unavailable'


def test_classifier_does_not_invent_spans():
    class Suspicious:
        def detect(self, text):
            return DetectorOutput(detector_name='test', version='1', risk='suspicious', probability=.5, duration_ms=1, reason='Uncertain')
    result = ContentInspector(detector=Suspicious()).inspect(ContentEnvelope(
        source_id='test', content_id='test', origin_trust='untrusted', data_sensitivity='public', content='Ordinary document.'))
    assert result.decision == ContentDecision.HOLD_FOR_REVIEW
    assert result.findings == []
    assert result.sanitized_content is None
