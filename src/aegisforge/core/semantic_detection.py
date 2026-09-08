from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, runtime_checkable


class SemanticVerdict(StrEnum):
    """Provider-independent labels returned by semantic detectors."""

    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class SemanticAssessment:
    """Explainable semantic evidence; never an authorization decision by itself."""

    verdict: SemanticVerdict
    score: float
    category: str
    reason: str
    detector: str
    detector_version: str
    latency_ms: float

    def __post_init__(self) -> None:
        if not 0.0 <= self.score <= 1.0:
            raise ValueError("semantic score must be between 0.0 and 1.0")
        if self.latency_ms < 0.0:
            raise ValueError("semantic latency must be non-negative")
        if not self.detector.strip():
            raise ValueError("semantic detector name must not be empty")
        if not self.detector_version.strip():
            raise ValueError("semantic detector version must not be empty")
        if not self.reason.strip():
            raise ValueError("semantic assessment reason must not be empty")

    @property
    def malicious(self) -> bool:
        return self.verdict is SemanticVerdict.MALICIOUS


@runtime_checkable
class SemanticDetector(Protocol):
    """Contract implemented by local or remote semantic detection providers."""

    @property
    def name(self) -> str:
        """Stable provider name used in evidence and metrics."""

    @property
    def version(self) -> str:
        """Model or implementation revision used for reproducibility."""

    def assess(self, prompt: str) -> SemanticAssessment:
        """Return evidence only; callers retain the final policy decision."""
