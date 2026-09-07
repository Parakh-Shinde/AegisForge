from datetime import UTC, datetime
from pathlib import Path

from aegisforge.core.provenance import (
    build_evaluation_provenance,
    sha256_file,
    sha256_file_set,
)


def test_file_fingerprint_changes_with_content(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus.json"
    corpus.write_text("first", encoding="utf-8")
    first = sha256_file(corpus)

    corpus.write_text("second", encoding="utf-8")

    assert sha256_file(corpus) != first


def test_file_set_fingerprint_is_order_independent(tmp_path: Path) -> None:
    first = tmp_path / "a.py"
    second = tmp_path / "b.py"
    first.write_text("a", encoding="utf-8")
    second.write_text("b", encoding="utf-8")

    assert sha256_file_set((first, second)) == sha256_file_set((second, first))


def test_provenance_records_reproducible_evaluation_identity(tmp_path: Path) -> None:
    corpus = tmp_path / "holdout.json"
    detector = tmp_path / "guard.py"
    corpus.write_text("[]", encoding="utf-8")
    detector.write_text("RULES = ()", encoding="utf-8")
    timestamp = datetime(2026, 9, 7, 12, 30, tzinfo=UTC)

    result = build_evaluation_provenance(
        corpus_name="holdout-v1",
        corpus_classification="holdout",
        corpus_path=corpus,
        detector_version="0.8.0",
        detector_paths=(detector,),
        evaluated_at=timestamp,
    )

    assert result.corpus_classification == "holdout"
    assert result.detector_version == "0.8.0"
    assert result.evaluated_at == "2026-09-07T12:30:00Z"
    assert len(result.corpus_sha256) == 64
    assert len(result.detector_sha256) == 64
