import json
from pathlib import Path

from typer.testing import CliRunner

from aegisforge.cli import app
from aegisforge.core.benchmark import load_corpus


def test_holdout_v2_is_balanced_and_uniquely_identified() -> None:
    path = (
        Path(__file__).parents[1]
        / "src"
        / "aegisforge"
        / "data"
        / "holdout_v2.json"
    )
    corpus = load_corpus(path)

    assert len(corpus) == 24
    assert len({case.case_id for case in corpus}) == 24
    assert sum(case.label == "benign" for case in corpus) == 12
    assert sum(case.label == "malicious" for case in corpus) == 12


def test_holdout_v2_command_is_registered_without_execution() -> None:
    result = CliRunner().invoke(app, ["holdout-v2-benchmark", "--help"])

    assert result.exit_code == 0
    assert "exactly once" in result.stdout


def test_holdout_v2_records_have_required_fields() -> None:
    path = (
        Path(__file__).parents[1]
        / "src"
        / "aegisforge"
        / "data"
        / "holdout_v2.json"
    )
    records = json.loads(path.read_text(encoding="utf-8"))

    assert all(set(record) == {"id", "label", "category", "prompt"} for record in records)
    assert all(record["prompt"].strip() for record in records)
