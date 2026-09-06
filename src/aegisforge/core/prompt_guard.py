from __future__ import annotations

import re
from dataclasses import dataclass


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
)

_EDUCATIONAL_CONTEXT = re.compile(
    r"^(explain|describe|analyze|compare|why|how)\b.{0,80}"
    r"\b(detect|defend|security|attempt|risk)",
    re.I,
)


def inspect_prompt(prompt: str) -> tuple[GuardFinding, ...]:
    """Return explainable findings; never treats a model as a policy authority."""
    normalized = " ".join(prompt.split())[:20_000]
    findings: list[GuardFinding] = []
    educational = bool(_EDUCATIONAL_CONTEXT.search(normalized))
    for rule_id, severity, category, pattern, reason in _RULES:
        if not pattern.search(normalized):
            continue
        if category == "instruction_override" and educational:
            continue
        findings.append(GuardFinding(rule_id, severity, category, reason))
    return tuple(findings)
