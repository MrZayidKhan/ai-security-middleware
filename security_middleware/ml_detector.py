"""CPU-only advisory classifier; load only locally trained, trusted joblib files."""
from pathlib import Path
from time import perf_counter
from typing import Literal, Protocol

from pydantic import BaseModel, Field


class DetectorOutput(BaseModel):
    detector_name: str
    version: str
    risk: Literal['benign', 'suspicious', 'high_risk', 'unavailable']
    probability: float | None = Field(default=None, ge=0, le=1)
    duration_ms: float = Field(ge=0)
    reason: str


class Detector(Protocol):
    def detect(self, content: str) -> DetectorOutput: ...


class MLDetector:
    """Retain a vectorizer/classifier pipeline once per service instance.

    Joblib uses pickle: never load artifacts from an untrusted source.
    Suspicious is an uncertainty band, not a learned third class.
    """
    def __init__(self, artifact_path: Path) -> None:
        self._pipeline = None
        self._error = 'Trained classifier is missing.'
        try:
            import joblib
            artifact = joblib.load(artifact_path)
            if artifact.get('format_version') != 1 or artifact.get('labels') != [0, 1]:
                raise ValueError('Unsupported artifact metadata')
            pipeline = artifact['pipeline']
            if list(pipeline.classes_) != [0, 1]:
                raise ValueError('Incorrect classifier labels')
            pipeline.predict_proba(['artifact validation'])
            self._pipeline = pipeline
        except Exception as error:
            self._error = f'Classifier unavailable ({type(error).__name__}).'

    def detect(self, content: str) -> DetectorOutput:
        start = perf_counter()
        try:
            if self._pipeline is None:
                raise RuntimeError(self._error)
            if not content.strip() or len(content) > 20_000:
                raise ValueError('Input outside classifier limits')
            # Every character participates; overlap reduces boundary dilution.
            chunks = [content[i:i + 2000] for i in range(0, len(content), 1800)]
            probability = float(self._pipeline.predict_proba(chunks)[:, 1].max())
            risk = 'high_risk' if probability >= .7 else 'suspicious' if probability >= .3 else 'benign'
            return DetectorOutput(detector_name='tfidf-logistic', version='1', risk=risk,
                probability=probability, duration_ms=(perf_counter()-start)*1000,
                reason='Maximum chunk injection probability; no sentence localization.')
        except Exception as error:
            return DetectorOutput(detector_name='tfidf-logistic', version='1', risk='unavailable',
                duration_ms=(perf_counter()-start)*1000,
                reason=self._error if self._pipeline is None else f'Classifier inference failed ({type(error).__name__}).')
