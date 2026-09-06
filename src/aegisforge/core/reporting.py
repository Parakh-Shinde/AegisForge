from __future__ import annotations

import json
from pathlib import Path

from aegisforge.core.runner import RunResult


def write_json_report(result: RunResult, destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": "1.0",
        "run_id": result.run_id,
        "mode": result.mode.value,
        "started_at": result.started_at,
        "attack_succeeded": result.attack_succeeded,
        "detected": result.detected,
        "events": [event.to_dict() for event in result.events],
        "alerts": [alert.to_dict() for alert in result.alerts],
    }
    destination.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return destination


def write_markdown_report(result: RunResult, destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    status = "SUCCEEDED" if result.attack_succeeded else "BLOCKED"
    lines = [
        "# AegisForge security validation report",
        "",
        f"- Run ID: `{result.run_id}`",
        f"- Lab mode: **{result.mode.value}**",
        f"- Attack outcome: **{status}**",
        f"- Correlated detection: **{'YES' if result.detected else 'NO'}**",
        f"- Events: **{len(result.events)}**",
        f"- Alerts: **{len(result.alerts)}**",
        "",
        "## Event timeline",
        "",
        "| Action | Outcome | Source | Target | Techniques |",
        "| --- | --- | --- | --- | --- |",
    ]
    for event in result.events:
        techniques = ", ".join(event.technique_ids) or "—"
        lines.append(
            f"| {event.action} | {event.outcome} | {event.source} | "
            f"{event.target} | {techniques} |"
        )
    lines.extend(["", "## Alerts", ""])
    for alert in result.alerts:
        lines.append(
            f"- **{alert.severity.upper()} — {alert.title}** "
            f"(`{alert.rule_id}`): {alert.reason}"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "Vulnerable mode should allow synthetic cross-tenant staging. Secure mode should",
            "block it while retaining detection telemetry. All records are synthetic and",
            "all activity remains inside the local lab.",
            "",
        ]
    )
    destination.write_text("\n".join(lines), encoding="utf-8")
    return destination
