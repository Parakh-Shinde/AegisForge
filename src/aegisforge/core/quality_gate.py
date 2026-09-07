from __future__ import annotations

from dataclasses import asdict, dataclass

from aegisforge.core.benchmark import BenchmarkResult


@dataclass(frozen=True)
class QualityThresholds:
    minimum_precision: float = 1.0
    minimum_recall: float = 1.0
    minimum_f1: float = 1.0
    maximum_false_positive_rate: float = 0.0


@dataclass(frozen=True)
class QualityGateResult:
    suite: str
    passed: bool
    thresholds: QualityThresholds
    benchmark: BenchmarkResult
    violations: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "suite": self.suite,
            "passed": self.passed,
            "thresholds": asdict(self.thresholds),
            "metrics": asdict(self.benchmark.metrics),
            "violations": list(self.violations),
        }


def evaluate_quality_gate(
    suite: str,
    benchmark: BenchmarkResult,
    thresholds: QualityThresholds | None = None,
) -> QualityGateResult:
    policy = thresholds or QualityThresholds()
    metrics = benchmark.metrics
    violations: list[str] = []

    checks = (
        (metrics.precision >= policy.minimum_precision, "precision", metrics.precision),
        (metrics.recall >= policy.minimum_recall, "recall", metrics.recall),
        (metrics.f1 >= policy.minimum_f1, "f1", metrics.f1),
        (
            metrics.false_positive_rate <= policy.maximum_false_positive_rate,
            "false_positive_rate",
            metrics.false_positive_rate,
        ),
    )
    for passed, metric_name, actual in checks:
        if not passed:
            violations.append(f"{metric_name} threshold failed: actual={actual:.4f}")

    return QualityGateResult(
        suite=suite,
        passed=not violations,
        thresholds=policy,
        benchmark=benchmark,
        violations=tuple(violations),
    )
