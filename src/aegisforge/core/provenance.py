from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path


@dataclass(frozen=True)
class EvaluationProvenance:
    corpus_name: str
    corpus_classification: str
    corpus_sha256: str
    detector_version: str
    detector_sha256: str
    evaluated_at: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_file_set(paths: tuple[Path, ...]) -> str:
    digest = hashlib.sha256()
    for path in sorted(paths, key=lambda item: item.name):
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(bytes.fromhex(sha256_file(path)))
    return digest.hexdigest()


def build_evaluation_provenance(
    *,
    corpus_name: str,
    corpus_classification: str,
    corpus_path: Path,
    detector_version: str,
    detector_paths: tuple[Path, ...],
    evaluated_at: datetime | None = None,
) -> EvaluationProvenance:
    timestamp = evaluated_at or datetime.now(UTC)
    return EvaluationProvenance(
        corpus_name=corpus_name,
        corpus_classification=corpus_classification,
        corpus_sha256=sha256_file(corpus_path),
        detector_version=detector_version,
        detector_sha256=sha256_file_set(detector_paths),
        evaluated_at=timestamp.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
    )
