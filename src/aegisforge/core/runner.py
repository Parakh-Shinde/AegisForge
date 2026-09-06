from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4

from aegisforge.core.detection import evaluate
from aegisforge.core.events import Alert, Event
from aegisforge.core.lab import LabMode, LabTarget


@dataclass(frozen=True)
class RunResult:
    run_id: str
    mode: LabMode
    started_at: str
    events: tuple[Event, ...]
    alerts: tuple[Alert, ...]
    attack_succeeded: bool

    @property
    def detected(self) -> bool:
        return any(alert.rule_id == "AF-CORR-001" for alert in self.alerts)


def run_hero_scenario(mode: LabMode) -> RunResult:
    target = LabTarget.seeded(mode)
    actor = target.users["analyst-a"]
    events = target.upload_poisoned_document(actor)
    events.extend(target.invoke_document_tool(actor, "tenant-b-plan"))
    alerts = evaluate(events)
    attack_succeeded = bool(target.staged_records)
    return RunResult(
        run_id=str(uuid4()),
        mode=mode,
        started_at=datetime.now(UTC).isoformat(),
        events=tuple(events),
        alerts=tuple(alerts),
        attack_succeeded=attack_succeeded,
    )

