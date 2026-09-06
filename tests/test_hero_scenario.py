import json

from aegisforge.core.lab import LabMode
from aegisforge.core.reporting import write_json_report, write_markdown_report
from aegisforge.core.runner import run_hero_scenario


def test_vulnerable_mode_proves_attack_and_detection() -> None:
    result = run_hero_scenario(LabMode.VULNERABLE)
    assert result.attack_succeeded is True
    assert result.detected is True
    assert any(
        event.action == "api.cross_tenant_access" and event.outcome == "success"
        for event in result.events
    )


def test_secure_mode_blocks_attack_but_keeps_detection_evidence() -> None:
    result = run_hero_scenario(LabMode.SECURE)
    assert result.attack_succeeded is False
    assert result.detected is True
    assert any(
        event.action == "api.cross_tenant_access" and event.outcome == "blocked"
        for event in result.events
    )


def test_reports_are_reproducible_artifacts(tmp_path) -> None:
    result = run_hero_scenario(LabMode.VULNERABLE)
    json_path = write_json_report(result, tmp_path / "report.json")
    markdown_path = write_markdown_report(result, tmp_path / "report.md")
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["attack_succeeded"] is True
    assert payload["detected"] is True
    assert "AF-CORR-001" in markdown_path.read_text(encoding="utf-8")

