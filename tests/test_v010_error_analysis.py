import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).parents[1]
ANALYSIS_PATH = PROJECT_ROOT / "evaluation" / "v0.10-error-analysis.json"
REPORT_PATH = PROJECT_ROOT / "reports" / "holdout-v2-first-run.json"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_error_registry_matches_preserved_report() -> None:
    analysis = _load(ANALYSIS_PATH)
    report = _load(REPORT_PATH)
    expected = {
        case["case_id"]: (
            "false_positive" if not case["expected_malicious"] else "false_negative"
        )
        for case in report["cases"]
        if case["expected_malicious"] != case["predicted_malicious"]
    }
    actual = {
        error["case_id"]: error["error_type"]
        for error in analysis["errors"]
    }

    assert actual == expected
    assert analysis["summary"] == {
        "false_positives": 2,
        "false_negatives": 11,
        "total_errors": 13,
    }


def test_error_registry_is_bound_to_first_run_evidence() -> None:
    analysis = _load(ANALYSIS_PATH)
    report = _load(REPORT_PATH)

    assert analysis["source"]["report"] == "reports/holdout-v2-first-run.json"
    assert analysis["source"]["report_sha256"] == (
        "e47836361d6cd2d086bb97801bc748d06b1b1f6c04a5b089785699df5ac04020"
    )
    assert analysis["source"]["freeze_id"] == report["freeze_id"]
    assert analysis["source"]["original_classification"] == "holdout"
    assert analysis["source"]["development_classification"] == "adapted_regression"


def test_review_case_preserves_frozen_scoring_policy() -> None:
    analysis = _load(ANALYSIS_PATH)
    errors = {error["case_id"]: error for error in analysis["errors"]}

    assert analysis["scoring_policy"]["malicious_prediction"] == "block"
    assert analysis["scoring_policy"]["review_is_malicious_prediction"] is False
    assert errors["H2-M007"]["action"] == "review"
    assert errors["H2-M007"]["error_type"] == "false_negative"
