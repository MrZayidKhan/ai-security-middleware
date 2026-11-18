from pathlib import Path
import json
from types import SimpleNamespace
import numpy as np

import pytest

from security_middleware.horizon_detector import HorizonDetector


def test_missing_files_fail_closed(tmp_path):
    detector = HorizonDetector(tmp_path)
    assert detector.detect('Ordinary document.').risk == 'unavailable'


def test_corrupt_model_is_rejected(tmp_path):
    (tmp_path/'model_quantized.onnx').write_bytes(b'invalid model')
    detector = HorizonDetector(tmp_path)
    assert detector._session is None
    assert detector.detect('Anything').risk == 'unavailable'


def test_invalid_thresholds_rejected():
    with pytest.raises(ValueError):
        HorizonDetector(Path('unused'),review_threshold=.9,high_risk_threshold=.5)


@pytest.mark.parametrize('window,overlap', [(9000,64),(512,512),(512,-1)])
def test_invalid_windows_rejected(window,overlap):
    with pytest.raises(ValueError):
        HorizonDetector(Path('unused'),window_tokens=window,overlap_tokens=overlap)


def test_profile_for_another_model_is_rejected(tmp_path):
    (tmp_path/'advisory_profile.json').write_text(json.dumps({'revision':'other','mode':'advisory'}))
    with pytest.raises(ValueError):
        HorizonDetector.from_advisory_profile(tmp_path)


def test_late_window_attack_is_not_lost():
    detector = HorizonDetector.__new__(HorizonDetector)
    detector._np = np
    detector.review_threshold, detector.high_risk_threshold = .5, .9
    detector._error = 'test'
    tail = SimpleNamespace(ids=[2],attention_mask=[1],type_ids=[0])
    first = SimpleNamespace(ids=[1],attention_mask=[1],type_ids=[0],overflowing=[tail])
    detector._tokenizer = SimpleNamespace(encode=lambda text:first)
    def run(_,feed):
        return [np.array([[5.,-5.]]) if feed['input_ids'][0,0]==1 else np.array([[-5.,5.]])]
    detector._session = SimpleNamespace(get_inputs=lambda:[SimpleNamespace(name='input_ids')],run=run)
    result = detector.detect('A long document with an attack near its end.')
    assert result.risk == 'high_risk'
    assert result.probability > .99


@pytest.mark.parametrize('content',['','x'*20001])
def test_unsupported_input_is_unavailable(content):
    detector = HorizonDetector.__new__(HorizonDetector)
    detector._session = object()
    detector._error = 'test'
    assert detector.detect(content).risk == 'unavailable'
