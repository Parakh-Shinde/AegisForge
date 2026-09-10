import pytest

from aegisforge.core.semantic_detection import (
    SemanticAssessment,
    SemanticDetector,
    SemanticVerdict,
)


class StubSemanticDetector:
    name = "stub-semantic"
    version = "test-1"

    def assess(self, prompt: str) -> SemanticAssessment:
        return SemanticAssessment(
            verdict=SemanticVerdict.MALICIOUS,
            score=0.91,
            category="instruction_override",
            reason=f"Synthetic assessment for {len(prompt)} characters.",
            detector=self.name,
            detector_version=self.version,
            latency_ms=0.25,
        )


def test_detector_contract_is_runtime_checkable() -> None:
    assert isinstance(StubSemanticDetector(), SemanticDetector)


def test_assessment_exposes_malicious_convenience_property() -> None:
    assessment = StubSemanticDetector().assess("synthetic prompt")

    assert assessment.malicious is True
    assert assessment.score == 0.91
    assert assessment.detector_version == "test-1"


def test_non_malicious_verdict_is_not_reported_as_malicious() -> None:
    assessment = SemanticAssessment(
        verdict=SemanticVerdict.SUSPICIOUS,
        score=0.65,
        category="ambiguous",
        reason="Requires deterministic policy review.",
        detector="stub-semantic",
        detector_version="test-1",
        latency_ms=0.0,
    )

    assert assessment.malicious is False


@pytest.mark.parametrize("score", [-0.01, 1.01])
def test_assessment_rejects_out_of_range_scores(score: float) -> None:
    with pytest.raises(ValueError, match="semantic score"):
        SemanticAssessment(
            verdict=SemanticVerdict.BENIGN,
            score=score,
            category="benign",
            reason="Synthetic invalid score.",
            detector="stub-semantic",
            detector_version="test-1",
            latency_ms=0.0,
        )


def test_assessment_rejects_negative_latency() -> None:
    with pytest.raises(ValueError, match="semantic latency"):
        SemanticAssessment(
            verdict=SemanticVerdict.BENIGN,
            score=0.0,
            category="benign",
            reason="Synthetic invalid latency.",
            detector="stub-semantic",
            detector_version="test-1",
            latency_ms=-0.01,
        )
