from __future__ import annotations

from dataclasses import dataclass

from aegisforge.core.events import Alert, Event


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    action: str
    severity: str
    reason: str
    suspicious_outcomes: tuple[str, ...] = ("success", "blocked")

    def matches(self, event: Event) -> bool:
        return event.action == self.action and event.outcome in self.suspicious_outcomes


DEFAULT_RULES = (
    Rule(
        "AF-AI-001",
        "Suspicious instructions retrieved from RAG",
        "rag.retrieve_suspicious",
        "high",
        "Retrieved content contains an embedded tool instruction.",
    ),
    Rule(
        "AF-AI-002",
        "Agent invoked a sensitive document tool",
        "agent.tool_invocation",
        "medium",
        "The agent attempted a security-sensitive tool call after retrieval.",
    ),
    Rule(
        "AF-API-001",
        "Cross-tenant object access attempt",
        "api.cross_tenant_access",
        "critical",
        "Actor and resource tenant identifiers do not match.",
    ),
    Rule(
        "AF-APT-001",
        "Synthetic data staging observed",
        "data.stage",
        "high",
        "The agent attempted to stage a record in the local collector.",
    ),
)


def evaluate(events: list[Event], rules: tuple[Rule, ...] = DEFAULT_RULES) -> list[Alert]:
    alerts: list[Alert] = []
    for event in events:
        for rule in rules:
            if rule.matches(event):
                alerts.append(
                    Alert(
                        rule_id=rule.rule_id,
                        title=rule.title,
                        severity=rule.severity,
                        event_ids=(event.event_id,),
                        technique_ids=event.technique_ids,
                        reason=rule.reason,
                    )
                )

    attack_actions = {
        event.action
        for event in events
        if event.action
        in {"rag.retrieve_suspicious", "agent.tool_invocation", "api.cross_tenant_access"}
    }
    if len(attack_actions) == 3:
        related = tuple(
            event.event_id
            for event in events
            if event.action in attack_actions
        )
        techniques = tuple(
            sorted({technique for event in events for technique in event.technique_ids})
        )
        alerts.append(
            Alert(
                rule_id="AF-CORR-001",
                title="RAG-to-API attack chain correlated",
                severity="critical",
                event_ids=related,
                technique_ids=techniques,
                reason=(
                    "RAG injection, sensitive tool use, and cross-tenant access "
                    "occurred in one run."
                ),
            )
        )
    return alerts
