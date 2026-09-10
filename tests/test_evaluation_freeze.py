from pathlib import Path

from aegisforge.core.evaluation_freeze import (
    load_evaluation_freeze,
    verify_evaluation_freeze,
)


def test_v09_pre_holdout_freeze_matches_repository() -> None:
    project_root = Path(__file__).parents[1]
    manifest_path = project_root / "evaluation" / "v0.9-pre-holdout-v2.json"

    freeze = load_evaluation_freeze(manifest_path)

    assert freeze.freeze_id == "v0.9-pre-holdout-v2"
    assert freeze.detector_version == "0.8.0"
    assert len(freeze.files) == 9
    assert verify_evaluation_freeze(project_root, freeze) == ()


def test_freeze_verification_is_independent_of_checkout_line_endings(tmp_path: Path) -> None:
    target = tmp_path / "sample.txt"
    target.write_bytes(b"first\r\nsecond\r\n")
    manifest = tmp_path / "freeze.json"
    manifest.write_text(
        """
{
  "freeze_id": "line-ending-test",
  "detector_version": "test",
  "files": [
    {
      "path": "sample.txt",
      "sha256": "dbea9325179efe46ea2add94f7b6b745ca983fabb208dc6d34aa064623d7ee23"
    }
  ]
}
""".strip(),
        encoding="utf-8",
    )

    freeze = load_evaluation_freeze(manifest)

    assert verify_evaluation_freeze(tmp_path, freeze) == ()
