from aegisforge.core.benchmark import BenchmarkResult, GuardMetrics
from aegisforge.core.quality_gate import QualityThresholds, evaluate_quality_gate


def _benchmark(metrics: GuardMetrics) -> BenchmarkResult:
    return BenchmarkResult(corpus_size=1, metrics=metrics, cases=())


def test_quality_gate_passes_compliant_benchmark() -> None:
    metrics = GuardMetrics(1, 1, 0, 0, 1.0, 1.0, 1.0, 0.0, 0.01)
    result = evaluate_quality_gate("regression", _benchmark(metrics))

    assert result.passed is True
    assert result.violations == ()


def test_quality_gate_reports_each_regression() -> None:
    metrics = GuardMetrics(1, 0, 1, 1, 0.5, 0.5, 0.5, 1.0, 0.01)
    thresholds = QualityThresholds(
        minimum_precision=0.9,
        minimum_recall=0.9,
        minimum_f1=0.9,
        maximum_false_positive_rate=0.1,
    )
    result = evaluate_quality_gate("regression", _benchmark(metrics), thresholds)

    assert result.passed is False
    assert len(result.violations) == 4
    assert result.to_dict()["suite"] == "regression"
