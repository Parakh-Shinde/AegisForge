from __future__ import annotations

import re
from dataclasses import dataclass
from time import perf_counter

from aegisforge.core.normalization import normalize_prompt
from aegisforge.core.prompt_context import classify_context
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
        "objective_replacement",
        re.compile(
            r"\b(?:set aside|move past)\b.{0,48}\b(?:governing|trusted)\b.{0,24}"
            r"\b(?:direction|instruction|policy)s?\b.{0,64}\b(?:adopt|follow|use)\b"
            r".{0,40}\b(?:objective|instruction|request)\b"
        ),
        0.90,
    ),
    _Signal(
        "authority_extraction",
        re.compile(
            r"\b(?:administrator|developer|owner|security team)\b.{0,64}"
            r"\b(?:approved|authorized|granted)\b.{0,48}"
            r"\b(?:exception|access|permission)\b.{0,96}"
            r"\b(?:provide|reveal|show|return|disclose)\b.{0,48}"
            r"\b(?:confidential|protected|hidden|private)\b.{0,32}"
            r"\b(?:initialization text|instruction|configuration|prompt|data)s?\b"
        ),
        0.90,
    ),
    _Signal(
        "indirect_instruction",
        re.compile(
            r"\b(?:attached|retrieved|external)\b.{0,40}"
            r"\b(?:knowledge entry|document|content|message)\b.{0,48}"
            r"\b(?:authoritative|trusted|higher priority)\b.{0,80}"
            r"\b(?:carry out|execute|follow|perform)\b.{0,40}"
            r"\b(?:embedded|included|contained)\b.{0,24}"
            r"\b(?:action|instruction|request)s?\b"
        ),
        0.90,
    ),
    _Signal(
        "delegated_extraction",
        re.compile(
            r"\b(?:ask|tell|instruct|have)\b.{0,32}"
            r"\b(?:secondary|another|subordinate)\b.{0,20}"
            r"\b(?:agent|model|assistant)\b.{0,48}"
            r"\b(?:retrieve|reveal|obtain|return|display)\b.{0,48}"
            r"\b(?:protected|hidden|private|confidential)\b.{0,24}"
            r"\b(?:configuration|instruction|prompt|secret|data)s?\b"
        ),
        0.90,
    ),
    _Signal(
        "fragmented_override",
        re.compile(
            r"\b(?:disregard|ignore|bypass)\b.{0,40}"
            r"\b(?:safeguard|control|restriction|rule|policy)s?\b"
        ),
        0.90,
    ),
    _Signal(
        "persistent_override",
        re.compile(
            r"\b(?:treat|regard|record)\b.{0,32}\b(?:this|following)\b.{0,24}"
            r"\b(?:request|message|instruction)\b.{0,40}"
            r"\b(?:permanent|persistent|lasting)\b.{0,32}"
            r"\b(?:policy|rule|instruction)\s+(?:update|change)\b.{0,64}"
            r"\b(?:apply|use|enforce|follow)\b.{0,48}"
            r"\b(?:future|later|subsequent)\b"
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
        return "1.3"

    def assess(self, prompt: str) -> SemanticAssessment:
        started_at = perf_counter()
        normalized = normalize_prompt(prompt).normalized.casefold()
        matches = tuple(signal for signal in _SIGNALS if signal.pattern.search(normalized))
        score = max((signal.weight for signal in matches), default=0.0)
        context = classify_context(normalized)

        if matches and (
            _DEFENSIVE_CONTEXT.search(normalized)
            or context.security_education
            or context.incident_response
        ):
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
