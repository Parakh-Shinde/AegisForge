from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class FrozenFile:
    path: str
    sha256: str


@dataclass(frozen=True)
class EvaluationFreeze:
    freeze_id: str
    detector_version: str
    files: tuple[FrozenFile, ...]


def load_evaluation_freeze(path: Path) -> EvaluationFreeze:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return EvaluationFreeze(
        freeze_id=payload["freeze_id"],
        detector_version=payload["detector_version"],
        files=tuple(FrozenFile(**entry) for entry in payload["files"]),
    )


def _canonical_text_sha256(path: Path) -> str:
    """Hash repository text consistently across LF and CRLF checkouts."""
    content = path.read_bytes().replace(b"\r\n", b"\n")
    return hashlib.sha256(content).hexdigest()


def verify_evaluation_freeze(
    project_root: Path,
    freeze: EvaluationFreeze,
) -> tuple[str, ...]:
    violations: list[str] = []
    for entry in freeze.files:
        target = project_root / entry.path
        if not target.is_file():
            violations.append(f"missing: {entry.path}")
        elif _canonical_text_sha256(target) != entry.sha256:
            violations.append(f"changed: {entry.path}")
    return tuple(violations)
