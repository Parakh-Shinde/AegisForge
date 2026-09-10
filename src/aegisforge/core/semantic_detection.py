from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
from time import perf_counter
from typing import Protocol, runtime_checkable


class SemanticVerdict(StrEnum):
    """Provider-independent labels returned by semantic detectors."""

    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNAVAILABLE = "unavailable"


class SemanticDetectorError(RuntimeError):
    """Expected provider failure that can be normalized into safe evidence."""


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
    schema_version: str = "1.0"

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

    def to_dict(self) -> dict[str, object]:
        value = asdict(self)
        value["verdict"] = self.verdict.value
        return value


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


def assess_with_fallback(prompt: str, detector: SemanticDetector) -> SemanticAssessment:
    """Convert expected provider failures into sanitized, measurable evidence."""
    started_at = perf_counter()
    try:
        return detector.assess(prompt)
    except (SemanticDetectorError, TimeoutError) as exc:
        latency_ms = (perf_counter() - started_at) * 1_000
        return SemanticAssessment(
            verdict=SemanticVerdict.UNAVAILABLE,
            score=0.0,
            category="detector_unavailable",
            reason=f"Semantic provider failed with {type(exc).__name__}.",
            detector=detector.name,
            detector_version=detector.version,
            latency_ms=latency_ms,
        )
