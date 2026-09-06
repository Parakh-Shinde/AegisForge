# AegisForge learning and delivery path

## Phase 0 — Foundation (current)

Learn: Python packaging, FastAPI, Pydantic, CLI design, and secure target
validation.

Evidence: passing tests and a CLI that rejects public targets.

## Phase 1 — Vulnerable AI/API target

Build a multi-tenant document assistant with secure and deliberately vulnerable
modes. Add Ollama only after the normal API behavior and authorization model are
tested.

## Phase 2 — Scenario runner

Define versioned YAML scenarios, validate them, and execute safe HTTP actions.
Every run produces structured evidence.

## Phase 3 — Telemetry and detection

Persist normalized events, implement deterministic rules, then correlate events
into a single attack timeline.

## Phase 4 — Hero attack chain

Demonstrate: poisoned RAG document → agent tool misuse → cross-tenant API access
attempt → harmless local staging → correlated incident.

## Phase 5 — Evaluation

Create labeled benign and malicious runs. Measure precision, recall, F1,
false-positive rate, and mean detection latency. Never invent measurements.

## Phase 6 — Portfolio release

Add architecture decisions, threat model, automated CI, demo recording, release
notes, screenshots, and a final evidence-based report.

## Teaching rule

For every module, be able to answer: what problem does it solve, what trust
boundary does it cross, how is it tested, what can fail, and what was postponed?

