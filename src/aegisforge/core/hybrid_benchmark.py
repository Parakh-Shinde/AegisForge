from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from aegisforge.core.benchmark import GuardMetrics, PromptCase, benchmark_guard, load_corpus
from aegisforge.core.hybrid_detection import (
    HybridAction,
    HybridPolicy,
    evaluate_hybrid_prompt,
)
from aegisforge.core.semantic_detection import SemanticDetector, SemanticVerdict


@dataclass(frozen=True)
class HybridCaseResult:
    case_id: str
    category: str
    expected_malicious: bool
    action: str
    predicted_malicious: bool
    rule_ids: tuple[str, ...]
    semantic_verdict: str
    semantic_score: float
    semantic_detector: str
    semantic_latency_ms: float


@dataclass(frozen=True)
class HybridMetrics:
    true_positives: int
    true_negatives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1: float
    false_positive_rate: float
    review_rate: float
    block_rate: float
    provider_failure_rate: float
    mean_semantic_latency_ms: float


@dataclass(frozen=True)
class MetricDelta:
    precision: float
    recall: float
    f1: float
    false_positive_rate: float


@dataclass(frozen=True)
class HybridBenchmarkResult:
    corpus_size: int
    rule_only: GuardMetrics
    hybrid: HybridMetrics
    delta: MetricDelta
    cases: tuple[HybridCaseResult, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "corpus_size": self.corpus_size,
            "rule_only": asdict(self.rule_only),
            "hybrid": asdict(self.hybrid),
            "delta": asdict(self.delta),
            "cases": [asdict(case) for case in self.cases],
            "interpretation": {
                "malicious_prediction": "block",
                "review_is_malicious_prediction": False,
            },
        }


def _divide(numerator: int | float, denominator: int | float) -> float:
    return numerator / denominator if denominator else 0.0


def benchmark_hybrid(
    detector: SemanticDetector,
    cases: tuple[PromptCase, ...] | None = None,
    *,
    policy: HybridPolicy | None = None,
) -> HybridBenchmarkResult:
    selected = load_corpus() if cases is None else cases
    rule_only = benchmark_guard(selected).metrics
    results: list[HybridCaseResult] = []

    for case in selected:
        decision = evaluate_hybrid_prompt(case.prompt, detector=detector, policy=policy)
        semantic = decision.semantic_assessment
        results.append(
            HybridCaseResult(
                case_id=case.case_id,
                category=case.category,
                expected_malicious=case.label == "malicious",
                action=decision.action.value,
                predicted_malicious=decision.action is HybridAction.BLOCK,
                rule_ids=tuple(finding.rule_id for finding in decision.rule_findings),
                semantic_verdict=semantic.verdict.value,
                semantic_score=semantic.score,
                semantic_detector=semantic.detector,
                semantic_latency_ms=round(semantic.latency_ms, 4),
            )
        )

    tp = sum(case.expected_malicious and case.predicted_malicious for case in results)
    tn = sum(not case.expected_malicious and not case.predicted_malicious for case in results)
    fp = sum(not case.expected_malicious and case.predicted_malicious for case in results)
    fn = sum(case.expected_malicious and not case.predicted_malicious for case in results)
    precision = _divide(tp, tp + fp)
    recall = _divide(tp, tp + fn)
    f1 = _divide(2 * precision * recall, precision + recall)
    size = len(results)
    hybrid = HybridMetrics(
        true_positives=tp,
        true_negatives=tn,
        false_positives=fp,
        false_negatives=fn,
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1=round(f1, 4),
        false_positive_rate=round(_divide(fp, fp + tn), 4),
        review_rate=round(
            _divide(sum(case.action == HybridAction.REVIEW.value for case in results), size),
            4,
        ),
        block_rate=round(
            _divide(sum(case.action == HybridAction.BLOCK.value for case in results), size),
            4,
        ),
        provider_failure_rate=round(
            _divide(
                sum(
                    case.semantic_verdict == SemanticVerdict.UNAVAILABLE.value
                    for case in results
                ),
                size,
            ),
            4,
        ),
        mean_semantic_latency_ms=round(
            _divide(sum(case.semantic_latency_ms for case in results), size),
            4,
        ),
    )
    delta = MetricDelta(
        precision=round(hybrid.precision - rule_only.precision, 4),
        recall=round(hybrid.recall - rule_only.recall, 4),
        f1=round(hybrid.f1 - rule_only.f1, 4),
        false_positive_rate=round(
            hybrid.false_positive_rate - rule_only.false_positive_rate,
            4,
        ),
    )
    return HybridBenchmarkResult(size, rule_only, hybrid, delta, tuple(results))


def write_hybrid_benchmark_report(
    result: HybridBenchmarkResult,
    output: Path,
) -> Path:
    """Write machine-readable or recruiter-readable comparison evidence."""
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = result.to_dict()
    if output.suffix.lower() == ".json":
        output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        return output

    rule = result.rule_only
    hybrid = result.hybrid
    delta = result.delta
    lines = [
        "# AegisForge hybrid benchmark",
        "",
        f"- Corpus size: **{result.corpus_size}**",
        f"- Rule-only F1: **{rule.f1:.4f}**",
        f"- Hybrid F1: **{hybrid.f1:.4f}**",
        f"- F1 delta: **{delta.f1:+.4f}**",
        f"- Rule-only recall: **{rule.recall:.4f}**",
        f"- Hybrid recall: **{hybrid.recall:.4f}**",
        f"- Recall delta: **{delta.recall:+.4f}**",
        f"- Review rate: **{hybrid.review_rate:.4f}**",
        f"- Block rate: **{hybrid.block_rate:.4f}**",
        f"- Provider failure rate: **{hybrid.provider_failure_rate:.4f}**",
        f"- Mean semantic latency: **{hybrid.mean_semantic_latency_ms:.4f} ms**",
        "",
        "Only BLOCK is counted as a malicious prediction. REVIEW is reported separately.",
        "",
        "These measurements apply only to the bundled synthetic regression corpus and must",
        "not be presented as general production performance.",
        "",
    ]
    output.write_text("\n".join(lines), encoding="utf-8")
    return output
