# AegisForge v0.10.0 — Holdout-driven detection hardening

AegisForge v0.10.0 turns the documented holdout-v2 generalization failures into
bounded detector improvements and permanent adapted-regression gates. It retains
the original first-run evidence and makes a clear distinction between fresh
evaluation and post-analysis regression testing.

## Highlights

- Bounded defensive handling for educational, quoted, translation, and
  incident-response prompts.
- Compositional override and authority-claim detection.
- Indirect instruction, delegation, fragmentation, and persistence detection.
- Covert exfiltration, credential access, and tool-abuse detection.
- Framing, role-play, encoding, social-engineering, and multilingual coverage.
- Deterministic semantic evidence version 1.5.
- A 24-case adapted holdout-v2 corpus with distinct `AR-H2-*` identifiers.
- Strict rule-only and hybrid regression gates published by CI.

## Regression evidence

| Mode | Precision | Recall | F1 | False-positive rate |
| --- | ---: | ---: | ---: | ---: |
| Rule-only adapted regression | 1.0000 | 1.0000 | 1.0000 | 0.0000 |
| Hybrid adapted regression | 1.0000 | 1.0000 | 1.0000 | 0.0000 |

Both modes record 12 true positives, 12 true negatives, zero false positives,
and zero false negatives. Hybrid provider-failure rate is zero.

These cases were adapted after inspecting holdout-v2 failures. The results are
regression evidence only and are not independent evaluation or a production
effectiveness claim.

## Preserved independent result

The original holdout-v2 first run remains unchanged:

| Mode | Precision | Recall | F1 | False-positive rate |
| --- | ---: | ---: | ---: | ---: |
| Rule-only holdout-v2 | 0.3333 | 0.0833 | 0.1333 | 0.1667 |
| Hybrid holdout-v2 | 0.3333 | 0.0833 | 0.1333 | 0.1667 |

## Validation

- Python 3.11 and 3.12 CI
- Ruff static analysis
- 127 warning-strict tests at release preparation
- Existing tuning and adapted-challenge quality gates
- New 24-case rule-only and hybrid regression gate
- Dependency audit and CodeQL
- Loopback-only safety boundary
- Model output cannot authorize or execute tools

## Evidence

- [v0.10 regression policy](V0.10_REGRESSION_GATE.md)
- [Holdout-v2 analysis](HOLDOUT_V2_RESULTS.md)
- [Evaluation protocol](EVALUATION_PROTOCOL.md)
- [Preserved first-run JSON](../reports/holdout-v2-first-run.json)

## Upgrade

```powershell
git pull --ff-only origin main
python -m pip install -e ".[dev]"
python -m ruff check .
python -m pytest -W error
aegisforge doctor
aegisforge benchmark-gate
aegisforge v010-regression-gate
```

Do not rerun or overwrite the preserved holdout-v2 first-run report.
