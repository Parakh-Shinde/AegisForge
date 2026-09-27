# API prompt-enforcement boundary

AegisForge exposes `POST /v1/security/prompts/enforce` as a policy boundary for
untrusted prompt input. The endpoint evaluates the request with deterministic
rules and the transparent semantic reference provider before any downstream
model or tool handling.

## Request

```json
{
  "prompt": "Explain least privilege in cloud security."
}
```

Prompt length is constrained to 1–20,000 characters.

## Deployment modes

Set `AEGISFORGE_ENFORCEMENT_MODE` to one of:

| Mode | Behavior |
| --- | --- |
| `observe` | Record the original decision but accept the request. |
| `review` | Allow benign requests and hold non-allow decisions for review. |
| `block` | Enforce the original allow, review, or block action. |

The safe default is `block`. Invalid values fail configuration during startup.

## Effective outcomes

| Effective action | HTTP status | Accepted |
| --- | ---: | --- |
| `allow` | 200 | true |
| `review` | 202 | false |
| `block` | 403 | false |

Every response includes both the original decision and effective enforcement outcome:
mode, original action, effective action, and acceptance. It also includes rule findings, semantic
assessment, reasons, decision sources, and the safety invariant
`tool_execution_allowed: false`.

This endpoint evaluates policy only. It does not call a language model, execute
tools, or grant authorization. Correlation identifiers and structured audit sinks are introduced in later v0.11 changes.
