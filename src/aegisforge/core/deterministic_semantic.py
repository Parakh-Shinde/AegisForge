from __future__ import annotations

import re
from dataclasses import dataclass
from time import perf_counter

from aegisforge.core.normalization import normalize_prompt
from aegisforge.core.semantic_detection import SemanticAssessment, SemanticVerdict


@dataclass(frozen=True)
class _Signal:
    category: str
    pattern: re.Pattern[str]
    weight: float


_SIGNALS = (
    _Signal(
        "instruction_override",
        re.compile(
            r"\b(?:disregard|ignore|replace|supersede)\b.{0,48}"
            r"\b(?:instruction|policy|rule|objective)s?\b"
        ),
        0.90,
    ),
    _Signal(
        "instruction_override",
        re.compile(
            r"\b(?:alternate|new|hidden)\s+(?:instruction|objective|task)s?\b"
        ),
        0.70,
    ),
    _Signal(
        "secret_extraction",
        re.compile(
            r"\b(?:reveal|print|return|show|expose)\b.{0,48}"
            r"\b(?:secret|credential|system prompt|protected instruction)s?\b"
        ),
        0.90,
    ),
    _Signal(
        "tool_abuse",
        re.compile(
            r"\b(?:execute|invoke|run|call)\b.{0,48}"
            r"\b(?:tool|command|shell|function)s?\b"
        ),
        0.65,
    ),
)

_DEFENSIVE_CONTEXT = re.compile(
    r"\b(?:awareness|defensive|education|example|quote|training)\b"
)


class DeterministicSemanticDetector:
    """Transparent reference detector for reproducible hybrid experiments."""

    @property
    def name(self) -> str:
        return "aegisforge-deterministic-semantic"

    @property
    def version(self) -> str:
        return "1.0"

    def assess(self, prompt: str) -> SemanticAssessment:
        started_at = perf_counter()
        normalized = normalize_prompt(prompt).casefold()
        matches = tuple(signal for signal in _SIGNALS if signal.pattern.search(normalized))
        score = max((signal.weight for signal in matches), default=0.0)

        if matches and _DEFENSIVE_CONTEXT.search(normalized):
            score = min(score, 0.55)

        if score >= 0.85:
            verdict = SemanticVerdict.MALICIOUS
        elif score >= 0.60:
            verdict = SemanticVerdict.SUSPICIOUS
        else:
            verdict = SemanticVerdict.BENIGN

        category = max(matches, key=lambda signal: signal.weight).category if matches else "none"
        reason = (
            f"Matched {len(matches)} transparent semantic signal(s)."
            if matches
            else "No transparent semantic signals matched."
        )
        return SemanticAssessment(
            verdict=verdict,
            score=score,
            category=category,
            reason=reason,
            detector=self.name,
            detector_version=self.version,
            latency_ms=(perf_counter() - started_at) * 1_000,
        )
