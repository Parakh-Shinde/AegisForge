from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum

from aegisforge.core.prompt_guard import GuardFinding, inspect_prompt
from aegisforge.core.semantic_detection import (
    SemanticAssessment,
    SemanticDetector,
    SemanticVerdict,
    assess_with_fallback,
)


class HybridAction(StrEnum):
    """Policy outcomes produced from rule and semantic evidence."""

    ALLOW = "allow"
    REVIEW = "review"
    BLOCK = "block"


@dataclass(frozen=True)
class HybridPolicy:
    """Thresholds remain application policy rather than provider policy."""

    review_threshold: float = 0.60
    block_threshold: float = 0.85
    review_when_unavailable: bool = True

    def __post_init__(self) -> None:
        if not 0.0 <= self.review_threshold <= 1.0:
            raise ValueError("review threshold must be between 0.0 and 1.0")
        if not 0.0 <= self.block_threshold <= 1.0:
            raise ValueError("block threshold must be between 0.0 and 1.0")
        if self.review_threshold > self.block_threshold:
            raise ValueError("review threshold must not exceed block threshold")


@dataclass(frozen=True)
class HybridDecision:
    action: HybridAction
    rule_findings: tuple[GuardFinding, ...]
    semantic_assessment: SemanticAssessment
    reasons: tuple[str, ...]
    decision_sources: tuple[str, ...]
    tool_execution_allowed: bool = False
    schema_version: str = "1.0"

    @property
    def blocked(self) -> bool:
        return self.action is HybridAction.BLOCK

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "action": self.action.value,
            "blocked": self.blocked,
            "tool_execution_allowed": self.tool_execution_allowed,
            "decision_sources": list(self.decision_sources),
            "reasons": list(self.reasons),
            "rule_findings": [asdict(finding) for finding in self.rule_findings],
            "semantic_assessment": self.semantic_assessment.to_dict(),
        }


def _decision(
    action: HybridAction,
    rule_findings: tuple[GuardFinding, ...],
    semantic: SemanticAssessment,
    reason: str,
    *sources: str,
) -> HybridDecision:
    return HybridDecision(
        action=action,
        rule_findings=rule_findings,
        semantic_assessment=semantic,
        reasons=(reason,),
        decision_sources=sources,
    )


def evaluate_hybrid_prompt(
    prompt: str,
    *,
    detector: SemanticDetector,
    policy: HybridPolicy | None = None,
) -> HybridDecision:
    """Combine independent evidence under deterministic application policy."""
    active_policy = policy or HybridPolicy()
    rule_findings = inspect_prompt(prompt)
    semantic = assess_with_fallback(prompt, detector)

    if rule_findings:
        return _decision(
            HybridAction.BLOCK,
            rule_findings,
            semantic,
            "deterministic prompt-security rule matched",
            "deterministic_rules",
        )

    if semantic.verdict is SemanticVerdict.MALICIOUS:
        if semantic.score >= active_policy.block_threshold:
            return _decision(
                HybridAction.BLOCK,
                rule_findings,
                semantic,
                "semantic malicious score met the block threshold",
                "semantic_detector",
                "threshold_policy",
            )
        return _decision(
            HybridAction.REVIEW,
            rule_findings,
            semantic,
            "semantic malicious verdict remained below the block threshold",
            "semantic_detector",
            "threshold_policy",
        )

    if semantic.verdict is SemanticVerdict.SUSPICIOUS:
        if semantic.score >= active_policy.review_threshold:
            return _decision(
                HybridAction.REVIEW,
                rule_findings,
                semantic,
                "semantic suspicious score met the review threshold",
                "semantic_detector",
                "threshold_policy",
            )
        return _decision(
            HybridAction.ALLOW,
            rule_findings,
            semantic,
            "semantic suspicious score remained below the review threshold",
            "semantic_detector",
            "threshold_policy",
        )

    if semantic.verdict is SemanticVerdict.UNAVAILABLE:
        if active_policy.review_when_unavailable:
            return _decision(
                HybridAction.REVIEW,
                rule_findings,
                semantic,
                "semantic detector was unavailable",
                "availability_policy",
            )
        return _decision(
            HybridAction.ALLOW,
            rule_findings,
            semantic,
            "policy permits rule-only evaluation when semantic detection is unavailable",
            "deterministic_rules",
            "availability_policy",
        )

    return _decision(
        HybridAction.ALLOW,
        rule_findings,
        semantic,
        "no deterministic or semantic malicious evidence was found",
        "deterministic_rules",
        "semantic_detector",
    )
