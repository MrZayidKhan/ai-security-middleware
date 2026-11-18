"""Optional pinned CPU ONNX detector; never fetch or execute remote model code."""
import hashlib
import json
from pathlib import Path
from time import perf_counter

from .ml_detector import DetectorOutput

REVISION = '2efc2ed5abecd21eb45c2506d231a65d6e392b85'
CHECKSUMS = {
    'model_quantized.onnx': '61cd0741cdbfcc229e32e1de1392f352736d87d1e8b3c2b67ad9836bb7910d5d',
    'tokenizer.json': '47834a7dbbb0c4324fe9569fe47955241594a9ee539c9e478755d6fbc51e5f46',
}


class HorizonDetector:
    """Advisory detector compatible with ContentInspector's Detector protocol.

    Load one instance per service. Keep disabled in production until appropriate
    deployment validation. A flag cannot establish which span can be removed.
    """
    def __init__(self, model_directory: Path, review_threshold=.5, high_risk_threshold=.9,
                 window_tokens=512, overlap_tokens=64):
        if not 0 <= review_threshold <= high_risk_threshold <= 1:
            raise ValueError('Invalid detector thresholds')
        if not 128 <= window_tokens <= 8192 or not 0 <= overlap_tokens < window_tokens-2:
            raise ValueError('Invalid token-window configuration')
        self._session = None
        self._error = 'Horizon model unavailable.'
        self.review_threshold = review_threshold
        self.high_risk_threshold = high_risk_threshold
        self.window_tokens = window_tokens
        self.overlap_tokens = overlap_tokens
        try:
            import numpy as np
            import onnxruntime as ort
            from tokenizers import Tokenizer
            for filename, expected in CHECKSUMS.items():
                with (model_directory/filename).open('rb') as handle:
                    if hashlib.file_digest(handle,'sha256').hexdigest() != expected:
                        raise ValueError('Model checksum mismatch')
            config = json.loads((model_directory/'config.json').read_text(encoding='utf-8'))
            if config['id2label'] != {'0':'SAFE','1':'INJECTION'}:
                raise ValueError('Unsupported model labels')
            options = ort.SessionOptions()
            options.intra_op_num_threads = 4
            tokenizer = Tokenizer.from_file(str(model_directory/'tokenizer.json'))
            tokenizer.enable_truncation(max_length=window_tokens,stride=overlap_tokens)
            session = ort.InferenceSession(str(model_directory/'model_quantized.onnx'),sess_options=options,providers=['CPUExecutionProvider'])
            self._np, self._tokenizer, self._session = np, tokenizer, session
        except Exception as error:
            self._error = f'Horizon unavailable ({type(error).__name__}).'

    def detect(self, content: str) -> DetectorOutput:
        start = perf_counter()
        try:
            if self._session is None:
                raise RuntimeError(self._error)
            if not content.strip() or len(content)>20000:
                raise ValueError('Input outside classifier limits')
            encoded = self._tokenizer.encode(content)
            probabilities = []
            for window in [encoded]+encoded.overflowing:
                values = dict(input_ids=window.ids,attention_mask=window.attention_mask,token_type_ids=window.type_ids)
                logits = self._session.run(None,{i.name:self._np.array([values[i.name]],dtype=self._np.int64) for i in self._session.get_inputs()})[0][0]
                exp = self._np.exp(logits-logits.max())
                probabilities.append(float((exp/exp.sum())[1]))
            probability = max(probabilities)
            risk = 'high_risk' if probability >= self.high_risk_threshold else 'suspicious' if probability >= self.review_threshold else 'benign'
            return DetectorOutput(detector_name='horizon-small-onnx',version=REVISION,risk=risk,
                                  probability=probability,duration_ms=(perf_counter()-start)*1000,
                                  reason='Maximum overlapping token-window score; no span localization or safety guarantee.')
        except Exception as error:
            return DetectorOutput(detector_name='horizon-small-onnx',version=REVISION,risk='unavailable',
                                  duration_ms=(perf_counter()-start)*1000,
                                  reason=self._error if self._session is None else f'Horizon inference failed ({type(error).__name__}).')
