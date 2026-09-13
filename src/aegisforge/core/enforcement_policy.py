from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum

from aegisforge.core.hybrid_detection import HybridAction, HybridDecision


class EnforcementMode(StrEnum):
    """Deployment behavior applied after hybrid security evaluation."""

    OBSERVE = "observe"
    REVIEW = "review"
    BLOCK = "block"


@dataclass(frozen=True)
class EnforcementOutcome:
    mode: EnforcementMode
    original_action: HybridAction
    effective_action: HybridAction
    accepted: bool
    status_code: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def apply_enforcement_mode(
    decision: HybridDecision,
    mode: EnforcementMode,
) -> EnforcementOutcome:
    """Map immutable decision evidence to deployment-specific handling."""
    if mode is EnforcementMode.OBSERVE:
        effective_action = HybridAction.ALLOW
    elif mode is EnforcementMode.REVIEW and decision.action is not HybridAction.ALLOW:
        effective_action = HybridAction.REVIEW
    else:
        effective_action = decision.action

    status_codes = {
        HybridAction.ALLOW: 200,
        HybridAction.REVIEW: 202,
        HybridAction.BLOCK: 403,
    }
    return EnforcementOutcome(
        mode=mode,
        original_action=decision.action,
        effective_action=effective_action,
        accepted=effective_action is HybridAction.ALLOW,
        status_code=status_codes[effective_action],
    )
