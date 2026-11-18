from pathlib import Path

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
