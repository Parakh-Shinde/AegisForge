import json

from typer.testing import CliRunner

from aegisforge.cli import app
from aegisforge.core.deterministic_semantic import DeterministicSemanticDetector
from aegisforge.core.hybrid_benchmark import (
    benchmark_hybrid,
    write_hybrid_benchmark_report,
)


def test_hybrid_benchmark_writes_json_and_markdown(tmp_path) -> None:
    result = benchmark_hybrid(DeterministicSemanticDetector())

    json_path = write_hybrid_benchmark_report(result, tmp_path / "hybrid.json")
    markdown_path = write_hybrid_benchmark_report(result, tmp_path / "hybrid.md")

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["corpus_size"] == 12
    assert payload["interpretation"]["malicious_prediction"] == "block"
    assert "Rule-only F1" in markdown_path.read_text(encoding="utf-8")
    assert "not be presented as general production performance" in (
        markdown_path.read_text(encoding="utf-8")
    )


def test_hybrid_benchmark_cli_emits_summary_and_reports(tmp_path) -> None:
    result = CliRunner().invoke(app, ["hybrid-benchmark", "--output", str(tmp_path)])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["corpus"] == "tuning"
    assert payload["corpus_size"] == 12
    assert set(payload["reports"]) == {
        str(tmp_path / "hybrid-benchmark.json"),
        str(tmp_path / "hybrid-benchmark.md"),
    }
    assert (tmp_path / "hybrid-benchmark.json").is_file()
    assert (tmp_path / "hybrid-benchmark.md").is_file()
