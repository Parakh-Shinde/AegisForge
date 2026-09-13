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
        "covert_exfiltration",
        re.compile(
            r"\b(?:return|provide|send|transmit)\b.{0,48}"
            r"\b(?:private|protected|confidential|hidden)\b.{0,32}"
            r"\b(?:setup text|initialization text|system prompt|instruction)s?\b.{0,64}"
            r"\b(?:one character|one token|small chunks?)\b.{0,32}"
            r"\b(?:at a time|separately)\b.{0,64}"
            r"\b(?:filter|detector|monitor)s?\b.{0,24}"
            r"\b(?:cannot|can't|avoid|bypass|evade)\b"
        ),
        0.90,
    ),
    _Signal(
        "credential_file_access",
        re.compile(
            r"\b(?:use|invoke|call)\b.{0,48}\b(?:function|tool|api)\b.{0,32}"
            r"\b(?:run|execute)\b.{0,32}\b(?:command|shell)\b.{0,48}"
            r"\b(?:reads?|access|open|copy)\b.{0,32}"
            r"\b(?:local\s+)?(?:credential|secret|token|key)\s+files?\b"
        ),
        0.95,
    ),
    _Signal(
        "roleplay_extraction",
        re.compile(
            r"\b(?:in a simulation|role[ -]?play|hypothetical)\b.{0,64}"
            r"\b(?:restriction|safeguard|rule)s?\b.{0,24}"
            r"\b(?:absent|disabled|removed|do not apply)\b.{0,64}"
            r"\b(?:disclose|reveal|show|provide)\b.{0,40}"
            r"\b(?:real|actual|hidden|protected)\b.{0,24}"
            r"\b(?:operating rules|instruction|system prompt|policy)s?\b"
        ),
        0.90,
    ),
    _Signal(
        "multilingual_extraction",
        re.compile(
            r"\b(?:omite|ignora|descarta)\b.{0,40}"
            r"\b(?:las\s+)?(?:reglas|instrucciones)\b.{0,24}"
            r"\b(?:anteriores|previas)\b.{0,64}\b(?:muestra|revela|expone)\b"
            r".{0,48}\b(?:instrucciones protegidas|prompt del sistema|reglas ocultas)\b"
        ),
        0.90,
    ),
    _Signal(
        "encoded_instruction",
        re.compile(
            r"\b(?:decode|decipher)\b.{0,48}\b(?:payload|content|string|message)\b"
            r".{0,64}\b(?:obey|follow|execute|apply)\b.{0,48}"
            r"\b(?:decoded|resulting)\b.{0,32}"
            r"\b(?:request|instruction|message)\b.{0,40}"
            r"\b(?:higher[ -]?priority|authoritative|trusted)\b"
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
        return "1.5"

    def assess(self, prompt: str) -> SemanticAssessment:
        started_at = perf_counter()
        normalized_prompt = normalize_prompt(prompt)
        inspection_texts = tuple(
            candidate.casefold() for candidate in normalized_prompt.inspection_texts
        )
        normalized = inspection_texts[0]
        matches = tuple(
            signal
            for signal in _SIGNALS
            if any(signal.pattern.search(candidate) for candidate in inspection_texts)
        )
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
