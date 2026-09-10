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

## v0.9 pre-holdout-v2 freeze

The machine-readable manifest at `evaluation/v0.9-pre-holdout-v2.json` freezes the
detector, hybrid policy implementation, comparison benchmark, and regression corpora.
The test suite verifies every listed SHA-256 fingerprint.

After this manifest is merged, none of its listed files may change before the first
holdout-v2 evaluation. If any frozen file must change, discard the unexecuted holdout,
create a new freeze identifier, and prepare a fresh holdout corpus.

The manifest records detector version `0.8.0` because the package remains at that
released version during v0.9 development. Package version `0.9.0` is assigned only
after the holdout evidence and release documentation are complete.
