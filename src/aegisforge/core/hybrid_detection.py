from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from aegisforge.core.prompt_guard import GuardFinding, inspect_prompt
from aegisforge.core.semantic_detection import (
    SemanticAssessment,
    SemanticDetector,
    SemanticVerdict,
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
    tool_execution_allowed: bool = False

    @property
    def blocked(self) -> bool:
        return self.action is HybridAction.BLOCK


def evaluate_hybrid_prompt(
    prompt: str,
    *,
    detector: SemanticDetector,
    policy: HybridPolicy | None = None,
) -> HybridDecision:
    """Combine independent evidence under deterministic application policy."""
    active_policy = policy or HybridPolicy()
    rule_findings = inspect_prompt(prompt)
    semantic = detector.assess(prompt)
    reasons: list[str] = []

    if rule_findings:
        reasons.append("deterministic prompt-security rule matched")
        return HybridDecision(HybridAction.BLOCK, rule_findings, semantic, tuple(reasons))

    if semantic.verdict is SemanticVerdict.MALICIOUS:
        if semantic.score >= active_policy.block_threshold:
            reasons.append("semantic malicious score met the block threshold")
            return HybridDecision(HybridAction.BLOCK, rule_findings, semantic, tuple(reasons))
        reasons.append("semantic malicious verdict remained below the block threshold")
        return HybridDecision(HybridAction.REVIEW, rule_findings, semantic, tuple(reasons))

    if semantic.verdict is SemanticVerdict.SUSPICIOUS:
        if semantic.score >= active_policy.review_threshold:
            reasons.append("semantic suspicious score met the review threshold")
            return HybridDecision(HybridAction.REVIEW, rule_findings, semantic, tuple(reasons))
        reasons.append("semantic suspicious score remained below the review threshold")
        return HybridDecision(HybridAction.ALLOW, rule_findings, semantic, tuple(reasons))

    if semantic.verdict is SemanticVerdict.UNAVAILABLE:
        if active_policy.review_when_unavailable:
            reasons.append("semantic detector was unavailable")
            return HybridDecision(HybridAction.REVIEW, rule_findings, semantic, tuple(reasons))
        reasons.append("policy permits rule-only evaluation when semantic detection is unavailable")
        return HybridDecision(HybridAction.ALLOW, rule_findings, semantic, tuple(reasons))

    reasons.append("no deterministic or semantic malicious evidence was found")
    return HybridDecision(HybridAction.ALLOW, rule_findings, semantic, tuple(reasons))
