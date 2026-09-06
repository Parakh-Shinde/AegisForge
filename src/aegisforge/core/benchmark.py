from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from time import perf_counter

from aegisforge.core.prompt_guard import inspect_prompt


@dataclass(frozen=True)
class PromptCase:
    case_id: str
    label: str
    category: str
    prompt: str


@dataclass(frozen=True)
class CaseResult:
    case_id: str
    expected_malicious: bool
    predicted_malicious: bool
    category: str
    rule_ids: tuple[str, ...]
    latency_ms: float


@dataclass(frozen=True)
class GuardMetrics:
    true_positives: int
    true_negatives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1: float
    false_positive_rate: float
    mean_latency_ms: float


@dataclass(frozen=True)
class BenchmarkResult:
    corpus_size: int
    metrics: GuardMetrics
    cases: tuple[CaseResult, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "corpus_size": self.corpus_size,
            "metrics": asdict(self.metrics),
            "cases": [asdict(case) for case in self.cases],
        }


def load_corpus(path: Path | None = None) -> tuple[PromptCase, ...]:
    source = path or Path(__file__).parent.parent / "data" / "prompt_corpus.json"
    records = json.loads(source.read_text(encoding="utf-8"))
    return tuple(
        PromptCase(record["id"], record["label"], record["category"], record["prompt"])
        for record in records
    )


def _divide(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def benchmark_guard(cases: tuple[PromptCase, ...] | None = None) -> BenchmarkResult:
    selected = cases or load_corpus()
    results: list[CaseResult] = []
    for case in selected:
        started = perf_counter()
        findings = inspect_prompt(case.prompt)
        elapsed_ms = (perf_counter() - started) * 1000
        results.append(
            CaseResult(
                case_id=case.case_id,
                expected_malicious=case.label == "malicious",
                predicted_malicious=bool(findings),
                category=case.category,
                rule_ids=tuple(finding.rule_id for finding in findings),
                latency_ms=round(elapsed_ms, 4),
            )
        )
    tp = sum(case.expected_malicious and case.predicted_malicious for case in results)
    tn = sum(not case.expected_malicious and not case.predicted_malicious for case in results)
    fp = sum(not case.expected_malicious and case.predicted_malicious for case in results)
    fn = sum(case.expected_malicious and not case.predicted_malicious for case in results)
    precision = _divide(tp, tp + fp)
    recall = _divide(tp, tp + fn)
    metrics = GuardMetrics(
        true_positives=tp,
        true_negatives=tn,
        false_positives=fp,
        false_negatives=fn,
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1=round(_divide(2 * precision * recall, precision + recall), 4),
        false_positive_rate=round(_divide(fp, fp + tn), 4),
        mean_latency_ms=round(sum(case.latency_ms for case in results) / len(results), 4),
    )
    return BenchmarkResult(len(results), metrics, tuple(results))


def write_benchmark_report(result: BenchmarkResult, output: Path) -> Path:
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = result.to_dict()
    if output.suffix.lower() == ".json":
        output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        return output
    metrics = result.metrics
    lines = [
        "# AegisForge guard benchmark",
        "",
        f"- Corpus size: **{result.corpus_size}**",
        f"- Precision: **{metrics.precision:.4f}**",
        f"- Recall: **{metrics.recall:.4f}**",
        f"- F1: **{metrics.f1:.4f}**",
        f"- False-positive rate: **{metrics.false_positive_rate:.4f}**",
        f"- Mean guard latency: **{metrics.mean_latency_ms:.4f} ms**",
        "",
        "## Confusion matrix",
        "",
        "| TP | TN | FP | FN |",
        "| ---: | ---: | ---: | ---: |",
        f"| {metrics.true_positives} | {metrics.true_negatives} | "
        f"{metrics.false_positives} | {metrics.false_negatives} |",
        "",
        "These measurements apply only to the bundled synthetic corpus and must not be",
        "presented as general production performance.",
        "",
    ]
    output.write_text("\n".join(lines), encoding="utf-8")
    return output
