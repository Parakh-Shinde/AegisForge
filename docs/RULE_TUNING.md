# Prompt-guard tuning record

## v0.4 baseline errors

| Case | Error | Cause |
| --- | --- | --- |
| B004 | False positive | Educational discussion matched override keywords |
| B006 | False positive | `show` and `token` were too broad together |
| M005 | False negative | Role-play paraphrase avoided the original verbs |

## v0.5 changes

- Suppress the instruction-override rule for clearly educational framing.
- Narrow secret extraction to stronger disclosure verbs.
- Add an explainable role-play/semantic-override rule.
- Lock all three cases into regression tests.

## v0.5.1 regression correction

The first narrowing of `AF-PROMPT-002` stopped matching `show the system
prompt`. The rule now treats `show` as suspicious only when paired with system
prompts, secrets, or credentials. Generic operational phrases such as `show a
checklist for rotating an expired token` remain allowed.

## Scientific limitation

The v0.5 rules were tuned after inspecting this corpus. Improved performance on
the same corpus measures regression correctness, not generalization. A separate
challenge set must be created before making comparative performance claims.
