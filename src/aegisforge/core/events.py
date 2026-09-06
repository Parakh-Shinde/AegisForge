from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4


@dataclass(frozen=True)
class Event:
    category: str
    action: str
    outcome: str
    source: str
    target: str
    technique_ids: tuple[str, ...] = ()
    evidence: dict[str, Any] = field(default_factory=dict)
    event_id: str = field(default_factory=lambda: str(uuid4()))
    occurred_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    schema_version: str = "1.0"

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["technique_ids"] = list(self.technique_ids)
        return value


@dataclass(frozen=True)
class Alert:
    rule_id: str
    title: str
    severity: str
    event_ids: tuple[str, ...]
    technique_ids: tuple[str, ...]
    reason: str

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["event_ids"] = list(self.event_ids)
        value["technique_ids"] = list(self.technique_ids)
        return value

