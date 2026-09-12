from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class PromptContext:
    quoted_or_translated: bool
    defensive_guidance: bool
    secure_architecture: bool
    credential_operations: bool
    security_education: bool
    incident_response: bool


def classify_context(text: str) -> PromptContext:
    return PromptContext(
        quoted_or_translated=bool(
            re.search(r"\b(quote|translate|awareness slide)\b", text, re.I)
        ),
        defensive_guidance=bool(
            re.search(r"\b(guidance|defenders?|detect|never to|prevention)\b", text, re.I)
        ),
        secure_architecture=bool(
            re.search(r"\b(how should|architecture|design)\b.{0,60}\bsecurely\b", text, re.I)
        ),
        credential_operations=bool(
            re.search(r"\b(rotation|rotate|expired|runbook)\b", text, re.I)
        ),
        security_education=bool(
            re.search(
                r"^(explain|describe|analyze|compare|why|how)\b.{0,120}"
                r"\b(warning sign|risk|indicator|attempt|attack)\b",
                text,
                re.I,
            )
        ),
        incident_response=bool(
            re.search(
                r"^(summarize|review|analyze)\b.{0,120}\b(evidence|log|alert|incident)\b"
                r".{0,120}\b(attempted|observed|reported)\b.{0,120}"
                r"\b(do not|don't|without)\s+(execute|run|invoke|call)\b",
                text,
                re.I,
            )
        ),
    )
