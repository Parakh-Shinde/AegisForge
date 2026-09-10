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
