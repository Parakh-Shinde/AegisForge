from __future__ import annotations

from dataclasses import asdict, dataclass

from aegisforge.core.hybrid_benchmark import HybridBenchmarkResult


@dataclass(frozen=True)
class RegressionThresholds:
    expected_corpus_size: int = 24
    minimum_precision: float = 1.0
    minimum_recall: float = 1.0
    minimum_f1: float = 1.0
    maximum_false_positive_rate: float = 0.0
    maximum_provider_failure_rate: float = 0.0


@dataclass(frozen=True)
class HybridRegressionGateResult:
    passed: bool
    thresholds: RegressionThresholds
    violations: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "passed": self.passed,
            "thresholds": asdict(self.thresholds),
            "violations": list(self.violations),
        }


def evaluate_hybrid_regression_gate(
    benchmark: HybridBenchmarkResult,
    thresholds: RegressionThresholds | None = None,
) -> HybridRegressionGateResult:
    policy = thresholds or RegressionThresholds()
    rule = benchmark.rule_only
    hybrid = benchmark.hybrid
    violations: list[str] = []

    checks = (
        (
            benchmark.corpus_size == policy.expected_corpus_size,
            "corpus_size",
            benchmark.corpus_size,
            policy.expected_corpus_size,
        ),
        (
            rule.precision >= policy.minimum_precision,
            "rule_precision",
            rule.precision,
            policy.minimum_precision,
        ),
        (
            rule.recall >= policy.minimum_recall,
            "rule_recall",
            rule.recall,
            policy.minimum_recall,
        ),
        (rule.f1 >= policy.minimum_f1, "rule_f1", rule.f1, policy.minimum_f1),
        (
            rule.false_positive_rate <= policy.maximum_false_positive_rate,
            "rule_false_positive_rate",
            rule.false_positive_rate,
            policy.maximum_false_positive_rate,
        ),
        (
            hybrid.precision >= policy.minimum_precision,
            "hybrid_precision",
            hybrid.precision,
            policy.minimum_precision,
        ),
        (
            hybrid.recall >= policy.minimum_recall,
            "hybrid_recall",
            hybrid.recall,
            policy.minimum_recall,
        ),
        (
            hybrid.f1 >= policy.minimum_f1,
            "hybrid_f1",
            hybrid.f1,
            policy.minimum_f1,
        ),
        (
            hybrid.false_positive_rate <= policy.maximum_false_positive_rate,
            "hybrid_false_positive_rate",
            hybrid.false_positive_rate,
            policy.maximum_false_positive_rate,
        ),
        (
            hybrid.provider_failure_rate <= policy.maximum_provider_failure_rate,
            "provider_failure_rate",
            hybrid.provider_failure_rate,
            policy.maximum_provider_failure_rate,
        ),
    )
    for passed, name, actual, expected in checks:
        if not passed:
            violations.append(
                f"{name} threshold failed: actual={actual}, expected={expected}"
            )

    return HybridRegressionGateResult(not violations, policy, tuple(violations))
