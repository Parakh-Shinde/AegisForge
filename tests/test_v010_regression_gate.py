import json
from pathlib import Path

from typer.testing import CliRunner

from aegisforge.cli import app
from aegisforge.core.benchmark import load_corpus
from aegisforge.core.deterministic_semantic import DeterministicSemanticDetector
from aegisforge.core.hybrid_benchmark import benchmark_hybrid
from aegisforge.core.regression_gate import evaluate_hybrid_regression_gate


def _adapted_corpus():
    path = (
        Path(__file__).parents[1]
        / "src"
        / "aegisforge"
        / "data"
        / "adapted_holdout_v2.json"
    )
    return load_corpus(path)


def test_adapted_corpus_is_complete_and_explicitly_reidentified() -> None:
    cases = _adapted_corpus()

    assert len(cases) == 24
    assert len({case.case_id for case in cases}) == 24
    assert all(case.case_id.startswith("AR-H2-") for case in cases)
    assert sum(case.label == "benign" for case in cases) == 12
    assert sum(case.label == "malicious" for case in cases) == 12


def test_v010_gate_prevents_historical_errors_from_returning() -> None:
    benchmark = benchmark_hybrid(
        DeterministicSemanticDetector(),
        _adapted_corpus(),
    )
    gate = evaluate_hybrid_regression_gate(benchmark)

    assert gate.passed is True
    assert gate.violations == ()
    assert benchmark.rule_only.false_positives == 0
    assert benchmark.rule_only.false_negatives == 0
    assert benchmark.hybrid.false_positives == 0
    assert benchmark.hybrid.false_negatives == 0


def test_v010_regression_cli_publishes_labeled_evidence(tmp_path) -> None:
    result = CliRunner().invoke(
        app,
        ["v010-regression-gate", "--output", str(tmp_path)],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["passed"] is True
    assert payload["classification"] == "adapted_regression"
    assert payload["independent_evaluation"] is False
    assert len(payload["reports"]) == 3
    assert (tmp_path / "v010-adapted-regression.json").is_file()
    assert (tmp_path / "v010-adapted-regression.md").is_file()
    assert (tmp_path / "v010-regression-gate.json").is_file()
