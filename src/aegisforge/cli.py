import json
from pathlib import Path

import typer
import uvicorn

from aegisforge import __version__
from aegisforge.config import settings
from aegisforge.core.ai_evaluation import evaluate_prompt
from aegisforge.core.benchmark import benchmark_guard, load_corpus, write_benchmark_report
from aegisforge.core.deterministic_semantic import DeterministicSemanticDetector
from aegisforge.core.evaluation_freeze import load_evaluation_freeze, verify_evaluation_freeze
from aegisforge.core.hybrid_benchmark import benchmark_hybrid, write_hybrid_benchmark_report
from aegisforge.core.lab import LabMode
from aegisforge.core.ollama import OllamaClient, OllamaError
from aegisforge.core.provenance import build_evaluation_provenance
from aegisforge.core.quality_gate import evaluate_quality_gate
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


@app.command("hybrid-benchmark")
def hybrid_benchmark(
    output: Path = typer.Option(Path("reports"), help="Hybrid benchmark report directory."),
) -> None:
    """Compare rule-only and deterministic hybrid detection on regression data."""
    result = benchmark_hybrid(DeterministicSemanticDetector())
    json_path = write_hybrid_benchmark_report(result, output / "hybrid-benchmark.json")
    markdown_path = write_hybrid_benchmark_report(result, output / "hybrid-benchmark.md")
    typer.echo(
        json.dumps(
            {
                "corpus": "tuning",
                "corpus_size": result.corpus_size,
                "rule_only": result.to_dict()["rule_only"],
                "hybrid": result.to_dict()["hybrid"],
                "delta": result.to_dict()["delta"],
                "reports": [str(json_path), str(markdown_path)],
            },
            indent=2,
        )
    )


@app.command("holdout-benchmark")
def holdout_benchmark(
    output: Path = typer.Option(Path("reports"), help="Holdout report directory."),
) -> None:
    """Run the versioned holdout once without using it as a tuning gate."""
    package_directory = Path(__file__).parent
    corpus_path = package_directory / "data" / "holdout_v1.json"
    core_directory = package_directory / "core"
    result = benchmark_guard(load_corpus(corpus_path))
    provenance = build_evaluation_provenance(
        corpus_name="holdout_v1",
        corpus_classification="holdout",
        corpus_path=corpus_path,
        detector_version=__version__,
        detector_paths=(
            core_directory / "normalization.py",
            core_directory / "prompt_context.py",
            core_directory / "prompt_guard.py",
        ),
    )
    payload = result.to_dict()
    payload["provenance"] = provenance.to_dict()
    report_path = output / "holdout-v1-first-run.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    typer.echo(
        json.dumps(
            {
                "corpus": "holdout_v1",
                "classification": "holdout",
                "metrics": payload["metrics"],
                "provenance": payload["provenance"],
                "report": str(report_path),
            },
            indent=2,
        )
    )


@app.command("holdout-v2-benchmark")
def holdout_v2_benchmark(
    output: Path = typer.Option(Path("reports"), help="Holdout-v2 report directory."),
) -> None:
    """Run the frozen hybrid detector against holdout-v2 exactly once."""
    project_root = Path(__file__).parents[2]
    manifest_path = project_root / "evaluation" / "v0.9-pre-holdout-v2.json"
    freeze = load_evaluation_freeze(manifest_path)
    violations = verify_evaluation_freeze(project_root, freeze)
    if violations:
        typer.echo(
            json.dumps(
                {
                    "executed": False,
                    "freeze_id": freeze.freeze_id,
                    "violations": list(violations),
                },
                indent=2,
            )
        )
        raise typer.Exit(code=3)

    corpus_path = Path(__file__).parent / "data" / "holdout_v2.json"
    result = benchmark_hybrid(
        DeterministicSemanticDetector(),
        load_corpus(corpus_path),
    )
    detector_paths = tuple(project_root / entry.path for entry in freeze.files[:7])
    provenance = build_evaluation_provenance(
        corpus_name="holdout_v2",
        corpus_classification="holdout",
        corpus_path=corpus_path,
        detector_version=freeze.detector_version,
        detector_paths=detector_paths,
    )
    payload = result.to_dict()
    payload["freeze_id"] = freeze.freeze_id
    payload["classification"] = "holdout"
    payload["provenance"] = provenance.to_dict()
    report_path = output / "holdout-v2-first-run.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    typer.echo(
        json.dumps(
            {
                "executed": True,
                "corpus": "holdout_v2",
                "classification": "holdout",
                "freeze_id": freeze.freeze_id,
                "rule_only": payload["rule_only"],
                "hybrid": payload["hybrid"],
                "delta": payload["delta"],
                "provenance": payload["provenance"],
                "report": str(report_path),
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
