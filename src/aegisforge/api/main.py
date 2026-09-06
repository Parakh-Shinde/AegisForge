from fastapi import FastAPI

from aegisforge import __version__
from aegisforge.config import settings
from aegisforge.core.ai_evaluation import evaluate_prompt
from aegisforge.core.benchmark import benchmark_guard
from aegisforge.core.lab import LabMode
from aegisforge.core.ollama import OllamaClient, OllamaError
from aegisforge.core.runner import run_hero_scenario
from aegisforge.core.target_policy import TargetPolicyError, validate_target
from aegisforge.models import (
    PromptEvaluationRequest,
    TargetValidationRequest,
    TargetValidationResponse,
)

app = FastAPI(
    title="AegisForge Control Plane",
    version=__version__,
    description="Lab-safe security test orchestration API",
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@app.post("/v1/targets/validate", response_model=TargetValidationResponse)
def validate_target_endpoint(request: TargetValidationRequest) -> TargetValidationResponse:
    try:
        target = validate_target(request.url, allow_private=settings.allow_private_targets)
    except TargetPolicyError as exc:
        return TargetValidationResponse(allowed=False, reason=str(exc))
    return TargetValidationResponse(
        allowed=True,
        hostname=target.hostname,
        addresses=list(target.resolved_addresses),
    )


@app.post("/v1/lab/demo/{mode}")
def run_demo_endpoint(mode: LabMode) -> dict[str, object]:
    result = run_hero_scenario(mode)
    return {
        "run_id": result.run_id,
        "mode": result.mode.value,
        "attack_succeeded": result.attack_succeeded,
        "detected": result.detected,
        "events": [event.to_dict() for event in result.events],
        "alerts": [alert.to_dict() for alert in result.alerts],
    }


@app.get("/v1/ai/models")
def list_local_models() -> dict[str, object]:
    try:
        models = OllamaClient().list_models()
    except OllamaError as exc:
        return {"available": False, "models": [], "reason": str(exc)}
    return {"available": True, "models": list(models), "reason": None}


@app.post("/v1/ai/evaluate")
def evaluate_local_prompt(request: PromptEvaluationRequest) -> dict[str, object]:
    try:
        result = evaluate_prompt(
            request.prompt,
            model=request.model,
            client=OllamaClient(),
            block_on_findings=request.block_on_findings,
        )
    except OllamaError as exc:
        return {"error": str(exc), "blocked": False}
    return result.to_dict()


@app.post("/v1/ai/benchmark/guard")
def benchmark_prompt_guard() -> dict[str, object]:
    return benchmark_guard().to_dict()
