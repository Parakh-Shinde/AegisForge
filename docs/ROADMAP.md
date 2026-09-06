# AegisForge delivery roadmap

## Project decision

AegisForge is the flagship portfolio project. Its core differentiator is an
end-to-end AI-to-API attack chain with unified telemetry, deterministic
detections, correlation, and measurable defensive results.

## Twelve-week build schedule

| Week | Milestone | Demonstrable outcome |
| --- | --- | --- |
| 1 | Foundation and safety | CLI, API, schemas, lab-target enforcement |
| 2 | Target application | Users, tenants, documents, authorization tests |
| 3 | Local AI integration | Ollama-backed assistant with controlled tools |
| 4 | Vulnerability modes | BOLA, BFLA, prompt injection, safe/unsafe modes |
| 5 | Scenario specification | Validated YAML plans and evidence capture |
| 6 | AI security runner | Direct/indirect injection and tool-abuse tests |
| 7 | API security runner | Authorization and business-logic test cases |
| 8 | Telemetry pipeline | Normalized, versioned events in PostgreSQL |
| 9 | Detection engine | Tested rules, alert evidence, false-positive cases |
| 10 | Hero attack chain | RAG poisoning to tool/API abuse correlation |
| 11 | Evaluation | Labeled runs, precision, recall, F1, latency |
| 12 | Release | Threat model, final report, demo, GitHub presentation |

## Definition of done

AegisForge is complete when a reviewer can install it, execute the same safe
attack and benign control runs, inspect evidence, reproduce measured results,
and understand the design trade-offs without private guidance.

## Deferred project schedule

These are intentionally deferred until AegisForge v1.0 is released.

| Priority | Project | Relationship to AegisForge | Start condition |
| --- | --- | --- | --- |
| 1 | ModelGuard MCP | Extract AegisForge tool authorization into an MCP proxy | AegisForge v1.0 released |
| 2 | RAGuard | Expand document provenance and poisoning detection | ModelGuard MVP complete |
| 3 | AuthZoo | Generalize multi-identity API authorization testing | RAGuard MVP complete |
| 4 | AgentScope | Productize agent telemetry and trajectory analysis | Three stable AegisForge integrations |
| 5 | CloudPath Emulator | Add cloud attack-path research | Cloud-security lab experience established |

SentinelLLM, SecureAgent Lab, LLM API Firewall, API Sentinel, and the Adversary
Playbook Runner are not separate near-term projects. Their strongest ideas are
absorbed into AegisForge modules to avoid duplicate repositories and shallow
implementations.

## Scope-control rule

No deferred project starts while an AegisForge v1.0 acceptance criterion is
incomplete. New ideas go into the backlog; they do not change the current
milestone unless they are required for the hero demonstration.

