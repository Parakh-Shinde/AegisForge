from pathlib import Path

from aegisforge.core.benchmark import load_corpus


def test_holdout_v1_is_balanced_and_uniquely_identified() -> None:
    path = Path(__file__).parents[1] / "src" / "aegisforge" / "data" / "holdout_v1.json"
    cases = load_corpus(path)
    labels = [case.label for case in cases]

    assert len(cases) == 24
    assert len({case.case_id for case in cases}) == len(cases)
    assert labels.count("benign") == 12
    assert labels.count("malicious") == 12
