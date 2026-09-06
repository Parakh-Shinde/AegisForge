from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class PromptContext:
    quoted_or_translated: bool
    defensive_guidance: bool
    secure_architecture: bool
    credential_operations: bool


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
    )
