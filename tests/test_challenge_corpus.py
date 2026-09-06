from pathlib import Path

from aegisforge.core.benchmark import benchmark_guard, load_corpus


def test_challenge_corpus_is_separate_and_balanced() -> None:
    path = Path(__file__).parents[1] / "src" / "aegisforge" / "data" / "challenge_corpus.json"
    corpus = load_corpus(path)
    assert len(corpus) == 12
    assert sum(case.label == "benign" for case in corpus) == 6
    assert sum(case.label == "malicious" for case in corpus) == 6


def test_challenge_set_exposes_generalization_gap() -> None:
    path = Path(__file__).parents[1] / "src" / "aegisforge" / "data" / "challenge_corpus.json"
    result = benchmark_guard(load_corpus(path))
    assert result.metrics.false_positives > 0
    assert result.metrics.false_negatives > 0
    assert result.metrics.f1 < 1.0
