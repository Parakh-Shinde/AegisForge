from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from aegisforge.core.events import Event


class LabMode(StrEnum):
    VULNERABLE = "vulnerable"
    SECURE = "secure"


@dataclass(frozen=True)
class User:
    user_id: str
    tenant_id: str
    role: str


@dataclass
class LabTarget:
    """Deterministic target used to prove authorization and detection behavior.

    It contains synthetic records only. Ollama integration will replace the
    deterministic agent decision in a later milestone while keeping these
    authorization controls and tests unchanged.
    """

    mode: LabMode
    users: dict[str, User] = field(default_factory=dict)
    documents: dict[str, dict[str, str]] = field(default_factory=dict)
    staged_records: list[str] = field(default_factory=list)

    @classmethod
    def seeded(cls, mode: LabMode) -> LabTarget:
        return cls(
            mode=mode,
            users={
                "analyst-a": User("analyst-a", "tenant-a", "analyst"),
                "victim-b": User("victim-b", "tenant-b", "analyst"),
            },
            documents={
                "tenant-b-plan": {
                    "tenant_id": "tenant-b",
                    "content": "Synthetic confidential roadmap: ORCHID-47",
                }
            },
        )

    def upload_poisoned_document(self, actor: User) -> list[Event]:
        return [
            Event(
                category="ai",
                action="document.upload",
                outcome="success",
                source=actor.user_id,
                target="knowledge-base",
                technique_ids=("AML.T0051",),
                evidence={
                    "tenant_id": actor.tenant_id,
                    "document_id": "poison-note",
                    "indicator": "embedded_tool_instruction",
                },
            ),
            Event(
                category="ai",
                action="rag.retrieve_suspicious",
                outcome="success",
                source="rag-service",
                target="agent",
                technique_ids=("AML.T0051",),
                evidence={"document_id": "poison-note", "risk": "indirect_prompt_injection"},
            ),
        ]

    def invoke_document_tool(self, actor: User, document_id: str) -> list[Event]:
        events = [
            Event(
                category="ai",
                action="agent.tool_invocation",
                outcome="success",
                source="document-agent",
                target="documents.read",
                technique_ids=("AML.T0053",),
                evidence={"actor_id": actor.user_id, "document_id": document_id},
            )
        ]
        document = self.documents[document_id]
        cross_tenant = document["tenant_id"] != actor.tenant_id
        allowed = self.mode is LabMode.VULNERABLE or not cross_tenant
        events.append(
            Event(
                category="api",
                action="api.cross_tenant_access",
                outcome="success" if allowed else "blocked",
                source=actor.user_id,
                target=document_id,
                technique_ids=("OWASP-API1:2023", "T1078"),
                evidence={
                    "actor_tenant": actor.tenant_id,
                    "resource_tenant": document["tenant_id"],
                    "control": "missing_object_authorization"
                    if allowed
                    else "tenant_authorization",
                },
            )
        )
        if allowed:
            self.staged_records.append(document["content"])
        events.append(
            Event(
                category="adversary",
                action="data.stage",
                outcome="success" if allowed else "blocked",
                source="document-agent",
                target="local-synthetic-collector",
                technique_ids=("T1074",),
                evidence={"records": 1 if allowed else 0, "synthetic_only": True},
            )
        )
        return events

