from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class EventCategory(StrEnum):
    AI = "ai"
    API = "api"
    ADVERSARY = "adversary"
    AUDIT = "audit"


class SecurityEvent(BaseModel):
    schema_version: str = "1.0"
    event_id: UUID = Field(default_factory=uuid4)
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    category: EventCategory
    action: str = Field(min_length=1, max_length=100)
    outcome: str = Field(pattern=r"^(success|failure|blocked|unknown)$")
    source: str = Field(min_length=1, max_length=100)
    target: str = Field(min_length=1, max_length=500)
    technique_ids: list[str] = Field(default_factory=list)
    evidence: dict[str, str | int | float | bool | None] = Field(default_factory=dict)


class TargetValidationRequest(BaseModel):
    url: str


class TargetValidationResponse(BaseModel):
    allowed: bool
    hostname: str | None = None
    addresses: list[str] = Field(default_factory=list)
    reason: str | None = None


class PromptEvaluationRequest(BaseModel):
    prompt: str = Field(min_length=1, max_length=20_000)
    model: str = Field(default="qwen2.5:3b", min_length=1, max_length=100)
    block_on_findings: bool = True
