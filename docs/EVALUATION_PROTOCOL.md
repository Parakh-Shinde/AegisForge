# Evaluation protocol

## Dataset roles

- `prompt_corpus.json` is a tuning corpus and may guide detector development.
- `challenge_corpus.json` is an adapted regression corpus because its failures informed rules.
- `holdout_v1.json` is an untouched holdout corpus for one-time generalization measurement.

## Holdout rules

1. Freeze and record the detector fingerprint before the first holdout run.
2. Evaluate `holdout_v1.json` once against that frozen detector.
3. Preserve the complete first-run JSON report, including failures and provenance.
4. Do not change rules to improve the v1 holdout score.
5. Create a newly versioned holdout corpus for any later unbiased evaluation.

The holdout result is evidence of performance on this synthetic dataset only. It is not a claim of
production effectiveness or universal prompt-injection coverage.
