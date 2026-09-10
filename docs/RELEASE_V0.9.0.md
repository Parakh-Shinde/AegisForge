# AegisForge v0.9.0 — Auditable hybrid prompt security

AegisForge v0.9.0 introduces a provider-independent semantic evidence layer and a
deterministic application policy that combines semantic and rule-based findings
without allowing model output to authorize tools.

## Highlights

- Semantic detector protocol with benign, suspicious, malicious, and unavailable verdicts.
- Hybrid policy with explicit allow, review, and block outcomes.
- Stable telemetry describing decision sources, reasons, scores, latency, and provider identity.
- Sanitized handling of semantic-provider timeouts and expected failures.
- Transparent deterministic reference provider for reproducible integration tests.
- Rule-only versus hybrid benchmark with JSON and Markdown evidence.
- SHA-256 evaluation freeze enforced across LF and CRLF checkouts.
- Fresh 24-case holdout-v2 corpus with guarded one-time execution and provenance.

## Validation

- Python 3.11 and 3.12 CI
- Ruff static analysis
- Warning-as-error pytest suite
- Regression benchmark quality gate
- Dependency auditing and CodeQL
- Loopback-only local-model and lab boundary
- Model output cannot directly execute tools

## Independent evaluation

| Mode | Precision | Recall | F1 | False-positive rate |
| --- | ---: | ---: | ---: | ---: |
| Rule-only holdout-v2 | 0.3333 | 0.0833 | 0.1333 | 0.1667 |
| Hybrid holdout-v2 | 0.3333 | 0.0833 | 0.1333 | 0.1667 |

The deterministic semantic reference provider produced no classification improvement
on the fresh holdout. Eleven malicious cases were not blocked, two benign cases were
blocked, and one tool-abuse case was routed to review.

This result is preserved as evidence of a substantial generalization gap. It prevents
the perfect tuning-corpus results from being presented as real-world effectiveness.
AegisForge v0.9 is an evaluation and architecture milestone, not a production-ready
prompt-injection classifier.

## Evidence

- [Evaluation protocol](EVALUATION_PROTOCOL.md)
- [Holdout-v2 analysis](HOLDOUT_V2_RESULTS.md)
- [Complete first-run JSON](../reports/holdout-v2-first-run.json)
- Freeze identifier: `v0.9-pre-holdout-v2`
- Report SHA-256: `e47836361d6cd2d086bb97801bc748d06b1b1f6c04a5b089785699df5ac04020`

## Upgrade

```powershell
git pull --ff-only origin main
python -m pip install -e ".[dev]"
python -m ruff check .
python -m pytest -W error
aegisforge doctor
aegisforge benchmark-gate
```

Do not rerun the preserved holdout-v2 evaluation. Its first-run report is the
authoritative evidence for this release.
