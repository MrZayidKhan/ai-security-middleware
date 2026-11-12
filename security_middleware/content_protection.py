"""Hybrid inspection for untrusted text returned by local tools."""

from __future__ import annotations

import base64
import re
import unicodedata
from enum import Enum
from time import perf_counter
from security_middleware.ml_detector import Detector, DetectorOutput

from pydantic import BaseModel, Field

from security_middleware.content_assessor import (
    AssessmentUnavailableError,
    ContentAssessor,
    ModelAssessment,
)


class OriginTrust(str, Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


class DataSensitivity(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"


class ContentDecision(str, Enum):
    PASS = "PASS"
    SANITIZE = "SANITIZE"
    HOLD_FOR_REVIEW = "HOLD_FOR_REVIEW"


class ContentEnvelope(BaseModel):
    """Text and the source metadata needed to assess it safely."""

    source_id: str = Field(min_length=1, max_length=128)
    content_id: str = Field(min_length=1, max_length=128)
    origin_trust: OriginTrust
    data_sensitivity: DataSensitivity
    content: str


class InspectionFinding(BaseModel):
    """A transparent rule match without a model-generated confidence score."""

    rule_id: str
    severity: str
    matched_text: str


class ContentInspectionResult(BaseModel):
    """Decision and safe-to-return text, if any."""

    decision: ContentDecision
    findings: list[InspectionFinding] = Field(default_factory=list)
    sanitized_content: str | None = None
    reason: str
    model_assessment: ModelAssessment | None = None
    normalized_content: str | None = None
    detector_outputs: list[DetectorOutput] = Field(default_factory=list)
    duration_ms: float = 0


class ContentInspector:
    """Combine validation, structural checks, rules, and a local-model signal."""

    _override_instruction = re.compile(
        r"(?im)^.*\b(?:ignore|disregard|override)\s+(?:all\s+)?"
        r"(?:previous|prior|system|earlier)\s+(?:instructions|rules|messages).*?$"
    )
    _data_exfiltration = re.compile(
        r"(?im)^.*\b(?:send|upload|reveal|share|exfiltrate)\b.*?"
        r"\b(?:confidential|secret|password|token|credential)s?\b.*?$"
    )
    _base64_candidate = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])")
    _zero_width = re.compile(r"[\u200b-\u200d\ufeff]")

    def __init__(
        self,
        max_content_characters: int = 20_000,
        assessor: ContentAssessor | None = None,
        require_assessment_for_untrusted: bool = False,
        detector: Detector | None = None,
    ) -> None:
        self._max_content_characters = max_content_characters
        if max_content_characters < 1:
            raise ValueError('Inspection size limit must be positive.')
        self._assessor = assessor
        self._require_assessment_for_untrusted = require_assessment_for_untrusted
        self._detector = detector

    def inspect(self, envelope: ContentEnvelope) -> ContentInspectionResult:
        """Aggregate advisory evidence without converting probability into spans."""
        start = perf_counter()
        result = self._inspect(envelope)
        if result.decision is ContentDecision.SANITIZE:
            remainder = result.sanitized_content or ''
            _, findings = self._normalize(remainder)
            if (self._data_exfiltration.search(remainder)
                    or self._override_instruction.search(remainder)
                    or any(item.severity == 'high' for item in findings)):
                result.decision = ContentDecision.HOLD_FOR_REVIEW
                result.sanitized_content = None
                result.reason = 'Suspicious instructions remain after sanitization.'
        if self._detector and result.normalized_content is not None:
            output = self._detect(result.normalized_content)
            result.detector_outputs.append(output)
            if output.risk != 'benign':
                prior_reason = result.reason if result.decision is ContentDecision.HOLD_FOR_REVIEW else ''
                result.decision = ContentDecision.HOLD_FOR_REVIEW
                result.sanitized_content = None
                result.reason = (prior_reason + f' Classifier requires review: {output.risk}. {output.reason}').strip()
            elif result.decision is ContentDecision.SANITIZE:
                # A document-level benign prediction cannot certify the remainder.
                residual = self._detect(result.sanitized_content or '')
                result.detector_outputs.append(residual)
                if residual.risk != 'benign':
                    result.decision = ContentDecision.HOLD_FOR_REVIEW
                    result.sanitized_content = None
                    result.reason = 'Sanitized remainder could not pass classifier inspection.'
        result.duration_ms = (perf_counter() - start) * 1000
        return result

    def _detect(self, content: str) -> DetectorOutput:
        start = perf_counter()
        try:
            return DetectorOutput.model_validate(self._detector.detect(content))
        except Exception:
            return DetectorOutput(detector_name='configured-detector', version='unknown',
                risk='unavailable', duration_ms=(perf_counter()-start)*1000,
                reason='Configured detector failed to return valid evidence.')

    def _inspect(self, envelope: ContentEnvelope) -> ContentInspectionResult:
        """Return PASS, SANITIZE, or HOLD based on visible rule matches."""
        validation_error = self._validate_content(envelope.content)
        if validation_error:
            return ContentInspectionResult(
                decision=ContentDecision.HOLD_FOR_REVIEW,
                reason=validation_error,
            )

        normalized_content, normalization_findings = self._normalize(envelope.content)
        validation_error = self._validate_content(normalized_content)
        if validation_error:
            return ContentInspectionResult(decision=ContentDecision.HOLD_FOR_REVIEW,
                findings=normalization_findings, reason='After normalization: ' + validation_error)
        if any(finding.severity == "high" for finding in normalization_findings):
            return ContentInspectionResult(
                decision=ContentDecision.HOLD_FOR_REVIEW,
                findings=normalization_findings,
                reason="Content contains an encoded suspicious payload.",
                normalized_content=normalized_content,
            )
        assessment = self._assess(normalized_content, envelope.origin_trust)
        if isinstance(assessment, ContentInspectionResult):
            assessment.findings.extend(normalization_findings)
            assessment.normalized_content = normalized_content
            return assessment

        exfiltration_matches = list(self._data_exfiltration.finditer(normalized_content))
        if exfiltration_matches:
            return ContentInspectionResult(
                decision=ContentDecision.HOLD_FOR_REVIEW,
                findings=[
                    InspectionFinding(
                        rule_id="data-exfiltration-directive",
                        severity="high",
                        matched_text=match.group(0),
                    )
                    for match in exfiltration_matches
                ] + normalization_findings,
                reason="Content contains an instruction to expose sensitive data.",
                model_assessment=assessment,
                normalized_content=normalized_content,
            )

        if assessment and assessment.risk == "high_risk":
            return ContentInspectionResult(
                decision=ContentDecision.HOLD_FOR_REVIEW,
                findings=normalization_findings
                + [
                    InspectionFinding(
                        rule_id="local-model-high-risk",
                        severity="high",
                        matched_text=span,
                    )
                    for span in assessment.suspicious_spans
                ],
                reason="Local model classified the content as high risk.",
                model_assessment=assessment,
                normalized_content=normalized_content,
            )

        override_matches = list(self._override_instruction.finditer(normalized_content))
        if override_matches:
            sanitized_content = self._override_instruction.sub(
                "[Suspicious instruction removed.]", normalized_content
            )
            if assessment and assessment.risk == "suspicious":
                model_cleaned = self._sanitize_model_spans(
                    normalized_content, assessment.suspicious_spans
                )
                if model_cleaned is None:
                    return ContentInspectionResult(
                        decision=ContentDecision.HOLD_FOR_REVIEW,
                        reason="Model concerns could not be isolated reliably.",
                        model_assessment=assessment,
                        normalized_content=normalized_content,
                        findings=normalization_findings,
                    )
                sanitized_content = self._override_instruction.sub(
                    "[Suspicious instruction removed.]", model_cleaned
                )
            return ContentInspectionResult(
                decision=ContentDecision.SANITIZE,
                findings=[
                    InspectionFinding(
                        rule_id="instruction-override",
                        severity="medium",
                        matched_text=match.group(0),
                    )
                    for match in override_matches
                ] + normalization_findings,
                sanitized_content=sanitized_content,
                reason="Content contains an instruction that attempts to override context.",
                model_assessment=assessment,
                normalized_content=normalized_content,
            )

        if assessment and assessment.risk == "suspicious":
            sanitized_content = self._sanitize_model_spans(
                normalized_content, assessment.suspicious_spans
            )
            if sanitized_content is None:
                return ContentInspectionResult(
                    decision=ContentDecision.HOLD_FOR_REVIEW,
                    findings=normalization_findings,
                    reason="Local model found suspicious content without a removable excerpt.",
                    model_assessment=assessment,
                    normalized_content=normalized_content,
                )
            return ContentInspectionResult(
                decision=ContentDecision.SANITIZE,
                findings=normalization_findings
                + [
                    InspectionFinding(
                        rule_id="local-model-suspicious-span",
                        severity="medium",
                        matched_text=span,
                    )
                    for span in assessment.suspicious_spans
                ],
                sanitized_content=sanitized_content,
                reason="Local model identified a removable suspicious excerpt.",
                model_assessment=assessment,
                normalized_content=normalized_content,
            )

        return ContentInspectionResult(
            decision=ContentDecision.PASS,
            findings=normalization_findings,
            sanitized_content=normalized_content,
            reason=("No risk detected by the enabled checks; this is not a safety guarantee. "
                    + ("Local model assessment completed." if assessment else "Local model assessment was not used.")),
            model_assessment=assessment,
            normalized_content=normalized_content,
        )

    def _validate_content(self, content: str) -> str | None:
        if not content.strip():
            return "Content is blank after whitespace removal."
        if len(content) > self._max_content_characters:
            return "Content exceeds the configured inspection size limit."
        if "\x00" in content:
            return "Content contains a null byte."
        return None

    def _normalize(self, content: str) -> tuple[str, list[InspectionFinding]]:
        normalized = unicodedata.normalize("NFKC", content)
        findings: list[InspectionFinding] = []
        if normalized != content:
            findings.append(
                InspectionFinding(
                    rule_id="unicode-normalized",
                    severity="low",
                    matched_text="Unicode compatibility characters were normalized.",
                )
            )
        if self._zero_width.search(normalized):
            normalized = self._zero_width.sub("", normalized)
            findings.append(
                InspectionFinding(
                    rule_id="invisible-characters-removed",
                    severity="medium",
                    matched_text="Zero-width characters were removed before inspection.",
                )
            )
        for candidate in self._base64_candidate.findall(normalized):
            try:
                decoded = base64.b64decode(candidate, validate=True).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                continue
            if self._override_instruction.search(decoded) or self._data_exfiltration.search(decoded):
                findings.append(
                    InspectionFinding(
                        rule_id="encoded-suspicious-payload",
                        severity="high",
                        matched_text=candidate[:80],
                    )
                )
        return normalized, findings

    def _assess(
        self, content: str, origin_trust: OriginTrust
    ) -> ModelAssessment | ContentInspectionResult | None:
        if self._assessor is None:
            if self._require_assessment_for_untrusted and origin_trust is OriginTrust.UNTRUSTED:
                return ContentInspectionResult(
                    decision=ContentDecision.HOLD_FOR_REVIEW,
                    reason="Required local model assessment is not configured.",
                )
            return None
        try:
            return self._assessor.assess(content)
        except AssessmentUnavailableError:
            if origin_trust is OriginTrust.UNTRUSTED and self._require_assessment_for_untrusted:
                return ContentInspectionResult(
                    decision=ContentDecision.HOLD_FOR_REVIEW,
                    reason="Local model assessment is unavailable for untrusted content.",
                )
            return None

    @staticmethod
    def _sanitize_model_spans(content: str, spans: list[str]) -> str | None:
        if not spans or any(not span.strip() or span not in content for span in spans):
            return None
        # Locate every span against the original, then merge overlapping ranges.
        # Sequential string replacement can destroy a later span's prefix.
        ranges = []
        for span in spans:
            start = 0
            while (start := content.find(span, start)) != -1:
                ranges.append((start, start + len(span)))
                start += 1
        merged = []
        for start, end in sorted(ranges):
            if merged and start <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else:
                merged.append((start, end))
        for start, end in reversed(merged):
            content = content[:start] + '[Suspicious instruction removed.]' + content[end:]
        return content
