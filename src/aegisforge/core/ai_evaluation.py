from __future__ import annotations

from dataclasses import asdict, dataclass

from aegisforge.core.ollama import OllamaClient
from aegisforge.core.prompt_guard import GuardFinding, inspect_prompt


@dataclass(frozen=True)
class EvaluationResult:
    model: str
    blocked: bool
    findings: tuple[GuardFinding, ...]
    model_response: str | None
    tool_execution_allowed: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "model": self.model,
            "blocked": self.blocked,
            "tool_execution_allowed": self.tool_execution_allowed,
            "findings": [asdict(finding) for finding in self.findings],
            "model_response": self.model_response,
        }


def evaluate_prompt(
    prompt: str,
    *,
    model: str,
    client: OllamaClient,
    block_on_findings: bool = True,
) -> EvaluationResult:
    findings = inspect_prompt(prompt)
    if findings and block_on_findings:
        return EvaluationResult(model, True, findings, None)
    return EvaluationResult(model, False, findings, client.chat(model, prompt))

