"""Rule-based inspection for untrusted text returned by local tools."""

from __future__ import annotations

import re
from enum import Enum

from pydantic import BaseModel, Field


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


class ContentInspector:
    """Apply small transparent rules before untrusted text reaches the model."""

    _override_instruction = re.compile(
        r"(?im)^.*\b(?:ignore|disregard|override)\s+(?:all\s+)?"
        r"(?:previous|prior|system|earlier)\s+(?:instructions|rules|messages).*?$"
    )
    _data_exfiltration = re.compile(
        r"(?im)^.*\b(?:send|upload|reveal|share|exfiltrate)\b.*?"
        r"\b(?:confidential|secret|password|token|credential)s?\b.*?$"
    )

    def __init__(self, max_content_characters: int = 20_000) -> None:
        self._max_content_characters = max_content_characters

    def inspect(self, envelope: ContentEnvelope) -> ContentInspectionResult:
        """Return PASS, SANITIZE, or HOLD based on visible rule matches."""
        if len(envelope.content) > self._max_content_characters:
            return ContentInspectionResult(
                decision=ContentDecision.HOLD_FOR_REVIEW,
                reason="Content exceeds the configured inspection size limit.",
            )

        exfiltration_matches = list(self._data_exfiltration.finditer(envelope.content))
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
                ],
                reason="Content contains an instruction to expose sensitive data.",
            )

        override_matches = list(self._override_instruction.finditer(envelope.content))
        if override_matches:
            sanitized_content = self._override_instruction.sub(
                "[Suspicious instruction removed.]", envelope.content
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
                ],
                sanitized_content=sanitized_content,
                reason="Content contains an instruction that attempts to override context.",
            )

        return ContentInspectionResult(
            decision=ContentDecision.PASS,
            sanitized_content=envelope.content,
            reason="No configured suspicious instruction pattern matched.",
        )
