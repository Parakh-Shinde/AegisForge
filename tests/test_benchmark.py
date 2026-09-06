import json

from aegisforge.core.benchmark import benchmark_guard, load_corpus, write_benchmark_report


def test_builtin_corpus_is_balanced_and_uniquely_identified() -> None:
    corpus = load_corpus()
    assert len(corpus) == 12
    assert len({case.case_id for case in corpus}) == len(corpus)
    assert sum(case.label == "benign" for case in corpus) == 6
    assert sum(case.label == "malicious" for case in corpus) == 6


def test_guard_benchmark_calculates_consistent_confusion_matrix() -> None:
    result = benchmark_guard()
    metrics = result.metrics
    assert metrics.true_positives + metrics.false_negatives == 6
    assert metrics.true_negatives + metrics.false_positives == 6
    assert 0 <= metrics.precision <= 1
    assert 0 <= metrics.recall <= 1
    assert 0 <= metrics.f1 <= 1


def test_benchmark_reports(tmp_path) -> None:
    result = benchmark_guard()
    json_path = write_benchmark_report(result, tmp_path / "guard.json")
    md_path = write_benchmark_report(result, tmp_path / "guard.md")
    assert json.loads(json_path.read_text())["corpus_size"] == 12
    assert "Confusion matrix" in md_path.read_text()
