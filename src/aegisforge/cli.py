import json
from pathlib import Path

import typer
import uvicorn

from aegisforge import __version__
from aegisforge.config import settings
from aegisforge.core.ai_evaluation import evaluate_prompt
from aegisforge.core.benchmark import benchmark_guard, load_corpus, write_benchmark_report
from aegisforge.core.lab import LabMode
from aegisforge.core.ollama import OllamaClient, OllamaError
from aegisforge.core.quality_gate import evaluate_quality_gate
from aegisforge.core.provenance import build_evaluation_provenance
from aegisforge.core.reporting import write_json_report, write_markdown_report
from aegisforge.core.runner import run_hero_scenario
from aegisforge.core.target_policy import TargetPolicyError, validate_target

app = typer.Typer(help="AegisForge lab-safe purple-team CLI", no_args_is_help=True)


@app.command()
def doctor() -> None:
    """Check the local control-plane configuration."""
    typer.echo(f"AegisForge {__version__}")
    typer.echo(f"environment: {settings.environment}")
    typer.echo("safety policy: loopback-only")


@app.command("validate-target")
def validate_target_command(url: str) -> None:
    """Check whether a URL is inside the authorized lab boundary."""
    try:
        result = validate_target(url, allow_private=settings.allow_private_targets)
    except TargetPolicyError as exc:
        typer.echo(json.dumps({"allowed": False, "reason": str(exc)}, indent=2))
        raise typer.Exit(code=2) from exc
    typer.echo(
        json.dumps(
            {
                "allowed": True,
                "hostname": result.hostname,
                "addresses": result.resolved_addresses,
            },
            indent=2,
        )
    )


@app.command()
def serve() -> None:
    """Run the local AegisForge control API."""
    uvicorn.run(
        "aegisforge.api.main:app",
        host=settings.bind_host,
        port=settings.bind_port,
        reload=False,
    )


@app.command()
def demo(
    mode: LabMode = typer.Option(LabMode.VULNERABLE, help="Lab control mode."),
    output: Path = typer.Option(Path("reports"), help="Report directory."),
) -> None:
    """Run the synthetic RAG-to-API hero scenario."""
    result = run_hero_scenario(mode)
    json_path = write_json_report(result, output / f"{result.run_id}.json")
    markdown_path = write_markdown_report(result, output / f"{result.run_id}.md")
    summary = {
        "run_id": result.run_id,
        "mode": result.mode.value,
        "attack_succeeded": result.attack_succeeded,
        "detected": result.detected,
        "events": len(result.events),
        "alerts": len(result.alerts),
        "reports": [str(json_path), str(markdown_path)],
    }
    typer.echo(json.dumps(summary, indent=2))


@app.command("ollama-check")
def ollama_check() -> None:
    """Verify local Ollama connectivity and list installed models."""
    try:
        models = OllamaClient().list_models()
    except OllamaError as exc:
        typer.echo(json.dumps({"available": False, "reason": str(exc)}, indent=2))
        raise typer.Exit(code=2) from exc
    typer.echo(json.dumps({"available": True, "models": models}, indent=2))


@app.command("ai-evaluate")
def ai_evaluate(
    prompt: str = typer.Argument(..., help="Prompt to evaluate."),
    model: str = typer.Option("qwen2.5:3b", help="Installed local Ollama model."),
    observe: bool = typer.Option(
        False,
        "--observe",
        help="Record findings but allow the prompt to reach the model.",
    ),
) -> None:
    """Evaluate one prompt through the local AI security boundary."""
    try:
        result = evaluate_prompt(
            prompt,
            model=model,
            client=OllamaClient(),
            block_on_findings=not observe,
        )
    except OllamaError as exc:
        typer.echo(json.dumps({"error": str(exc)}, indent=2))
        raise typer.Exit(code=2) from exc
    typer.echo(json.dumps(result.to_dict(), indent=2))


@app.command("guard-benchmark")
def guard_benchmark(
    output: Path = typer.Option(Path("reports"), help="Benchmark report directory."),
) -> None:
    """Measure the prompt guard against the labeled synthetic corpus."""
    result = benchmark_guard()
    json_path = write_benchmark_report(result, output / "guard-benchmark.json")
    markdown_path = write_benchmark_report(result, output / "guard-benchmark.md")
    typer.echo(
        json.dumps(
            {
                "corpus_size": result.corpus_size,
                "metrics": result.to_dict()["metrics"],
                "reports": [str(json_path), str(markdown_path)],
            },
            indent=2,
        )
    )


@app.command("challenge-benchmark")
def challenge_benchmark(
    output: Path = typer.Option(Path("reports"), help="Benchmark report directory."),
) -> None:
    """Evaluate the guard against the separate adversarial challenge corpus."""
    corpus_path = Path(__file__).parent / "data" / "challenge_corpus.json"
    result = benchmark_guard(load_corpus(corpus_path))
    json_path = write_benchmark_report(result, output / "challenge-benchmark.json")
    markdown_path = write_benchmark_report(result, output / "challenge-benchmark.md")
    typer.echo(
        json.dumps(
            {
                "corpus": "challenge",
                "corpus_size": result.corpus_size,
                "metrics": result.to_dict()["metrics"],
                "reports": [str(json_path), str(markdown_path)],
            },
            indent=2,
        )
    )


@app.command("benchmark-gate")
def benchmark_gate() -> None:
    """Fail when a regression corpus falls below its quality policy."""
    data_directory = Path(__file__).parent / "data"
    core_directory = Path(__file__).parent / "core"
    detector_paths = (
        core_directory / "normalization.py",
        core_directory / "prompt_context.py",
        core_directory / "prompt_guard.py",
    )
    suites = (
        ("tuning", "tuning", data_directory / "prompt_corpus.json"),
        (
            "adapted_challenge",
            "adapted_regression",
            data_directory / "challenge_corpus.json",
        ),
    )
    results = []
    for name, classification, corpus_path in suites:
        gate = evaluate_quality_gate(name, benchmark_guard(load_corpus(corpus_path)))
        provenance = build_evaluation_provenance(
            corpus_name=name,
            corpus_classification=classification,
            corpus_path=corpus_path,
            detector_version=__version__,
            detector_paths=detector_paths,
        )
        suite_payload = gate.to_dict()
        suite_payload["provenance"] = provenance.to_dict()
        results.append((gate, suite_payload))
    passed = all(gate.passed for gate, _ in results)
    typer.echo(
        json.dumps(
            {
                "passed": passed,
                "suites": [payload for _, payload in results],
            },
            indent=2,
        )
    )
    if not passed:
        raise typer.Exit(code=1)
