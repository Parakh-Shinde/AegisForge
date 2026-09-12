from __future__ import annotations

import re
from dataclasses import dataclass

from aegisforge.core.normalization import normalize_prompt
from aegisforge.core.prompt_context import classify_context


@dataclass(frozen=True)
class GuardFinding:
    rule_id: str
    severity: str
    category: str
    reason: str


_RULES: tuple[tuple[str, str, str, re.Pattern[str], str], ...] = (
    (
        "AF-PROMPT-001",
        "high",
        "instruction_override",
        re.compile(r"\b(ignore|disregard|override)\b.{0,40}\b(instruction|prompt|policy)", re.I),
        "Input attempts to override trusted instructions.",
    ),
    (
        "AF-PROMPT-002",
        "high",
        "secret_extraction",
        re.compile(
            r"(?:\b(reveal|print|output|expose|disclose)\b.{0,40}"
            r"\b(system prompt|secret|token|credential|hidden configuration)"
            r"|\bshow\b.{0,40}\b(system prompt|secret|credential))",
            re.I,
        ),
        "Input requests protected instructions or secrets.",
    ),
    (
        "AF-PROMPT-003",
        "critical",
        "tool_abuse",
        re.compile(r"\b(call|invoke|use|execute)\b.{0,50}\b(admin|internal|shell|tool|api)", re.I),
        "Input attempts to trigger a privileged tool or API.",
    ),
    (
        "AF-PROMPT-004",
        "high",
        "semantic_override",
        re.compile(
            r"\b(pretend|assume)\b.{0,40}\b(rules|policy|instructions)\b"
            r".{0,30}\b(no longer|do not|don't)\b",
            re.I,
        ),
        "Input uses role-play language to invalidate trusted rules.",
    ),
    (
        "AF-PROMPT-005",
        "high",
        "paraphrased_override",
        re.compile(
            r"\b(forget|discard|abandon)\b.{0,40}\b(earlier|previous|prior)\b"
            r".{0,40}\b(directive|instruction|rule)s?\b",
            re.I,
        ),
        "Input paraphrases an instruction-override request.",
    ),
    (
        "AF-PROMPT-006",
        "high",
        "multilingual_override",
        re.compile(
            r"\b(pichle|purane)\b.{0,40}\b(nirdesh|instructions?|rules?)\b"
            r".{0,40}\b(bhool|ignore)\b",
            re.I,
        ),
        "Input contains a transliterated instruction-override request.",
    ),
    (
        "AF-PROMPT-007",
        "high",
        "objective_replacement",
        re.compile(
            r"\b(set aside|move past)\b.{0,48}\b(governing|trusted)\b.{0,24}"
            r"\b(direction|instruction|policy)s?\b.{0,64}\b(adopt|follow|use)\b"
            r".{0,40}\b(objective|instruction|request)\b",
            re.I,
        ),
        "Input replaces governing directions with an untrusted objective.",
    ),
    (
        "AF-PROMPT-008",
        "high",
        "authority_extraction",
        re.compile(
            r"\b(administrator|developer|owner|security team)\b.{0,64}"
            r"\b(approved|authorized|granted)\b.{0,48}\b(exception|access|permission)\b"
            r".{0,96}\b(provide|reveal|show|return|disclose)\b.{0,48}"
            r"\b(confidential|protected|hidden|private)\b.{0,32}"
            r"\b(initialization text|instruction|configuration|prompt|data)s?\b",
            re.I,
        ),
        "Input uses claimed authority to request protected initialization data.",
    ),
)

_EDUCATIONAL_CONTEXT = re.compile(
    r"^(explain|describe|analyze|compare|why|how)\b.{0,80}"
    r"\b(detect|defend|security|attempt|risk)",
    re.I,
)


def inspect_prompt(prompt: str) -> tuple[GuardFinding, ...]:
    """Return explainable findings; never treats a model as a policy authority."""
    normalized_prompt = normalize_prompt(prompt)
    findings: list[GuardFinding] = []
    for candidate in normalized_prompt.inspection_texts:
        educational = bool(_EDUCATIONAL_CONTEXT.search(candidate))
        context = classify_context(candidate)
        for rule_id, severity, category, pattern, reason in _RULES:
            if not pattern.search(candidate):
                continue
            if category == "instruction_override" and educational:
                continue
            if context.quoted_or_translated:
                continue
            if category in {"secret_extraction", "authority_extraction"} and (
                context.defensive_guidance
                or context.credential_operations
                or context.security_education
            ):
                continue
            if category == "tool_abuse" and (
                context.secure_architecture or context.incident_response
            ):
                continue
            finding = GuardFinding(rule_id, severity, category, reason)
            if finding not in findings:
                findings.append(finding)
    return tuple(findings)
