import pytest

from aegisforge.core.hybrid_detection import HybridAction, evaluate_hybrid_prompt
from aegisforge.core.semantic_detection import (
    SemanticAssessment,
    SemanticDetectorError,
    SemanticVerdict,
    assess_with_fallback,
)


class FixedDetector:
    name = "fixed-semantic"
    version = "test-2"

    def assess(self, prompt: str) -> SemanticAssessment:
        return SemanticAssessment(
            verdict=SemanticVerdict.MALICIOUS,
            score=0.92,
            category="semantic_override",
            reason=f"Synthetic assessment for {len(prompt)} characters.",
            detector=self.name,
            detector_version=self.version,
            latency_ms=0.25,
        )


class FailingDetector:
    name = "failing-semantic"
    version = "test-2"

    def __init__(self, error: Exception) -> None:
        self.error = error

    def assess(self, prompt: str) -> SemanticAssessment:
        raise self.error


def test_semantic_assessment_serializes_versioned_evidence() -> None:
    assessment = FixedDetector().assess("synthetic input")

    assert assessment.to_dict() == {
        "verdict": "malicious",
        "score": 0.92,
        "category": "semantic_override",
        "reason": "Synthetic assessment for 15 characters.",
        "detector": "fixed-semantic",
        "detector_version": "test-2",
        "latency_ms": 0.25,
        "schema_version": "1.0",
    }


def test_hybrid_decision_serializes_sources_and_safety_boundary() -> None:
    decision = evaluate_hybrid_prompt("Carry out the alternate objective.", detector=FixedDetector())
    payload = decision.to_dict()

    assert payload["action"] == "block"
    assert payload["blocked"] is True
    assert payload["tool_execution_allowed"] is False
    assert payload["decision_sources"] == ["semantic_detector", "threshold_policy"]
    assert payload["semantic_assessment"]["detector_version"] == "test-2"


@pytest.mark.parametrize("error", [TimeoutError(), SemanticDetectorError("provider failed")])
def test_expected_provider_failure_becomes_unavailable_evidence(error: Exception) -> None:
    assessment = assess_with_fallback("synthetic input", FailingDetector(error))

    assert assessment.verdict is SemanticVerdict.UNAVAILABLE
    assert assessment.score == 0.0
    assert assessment.category == "detector_unavailable"
    assert assessment.detector == "failing-semantic"
    assert assessment.latency_ms >= 0.0
    assert str(error) not in assessment.reason


def test_unavailable_evidence_routes_to_review() -> None:
    detector = FailingDetector(SemanticDetectorError("sensitive provider detail"))

    decision = evaluate_hybrid_prompt("Ordinary request.", detector=detector)

    assert decision.action is HybridAction.REVIEW
    assert decision.decision_sources == ("availability_policy",)
    assert decision.tool_execution_allowed is False


def test_unexpected_programming_error_is_not_silently_swallowed() -> None:
    detector = FailingDetector(ValueError("invalid provider implementation"))

    with pytest.raises(ValueError, match="invalid provider implementation"):
        assess_with_fallback("synthetic input", detector)
