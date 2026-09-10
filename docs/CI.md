# Continuous integration

The CI workflow runs on pull requests to `main`, pushes to `main`, and manual dispatches.

Each supported Python version executes these controls:

1. Install AegisForge and its development dependencies.
2. Run Ruff static checks.
3. Run the test suite with warnings treated as errors.
4. Generate tuning, adapted-regression, and rule-only versus hybrid reports.
5. Enforce benchmark precision, recall, F1, and false-positive-rate thresholds.
6. Upload the reports as a 30-day GitHub Actions artifact, including on failed runs.
7. Verify the installed CLI entry point.

Holdout datasets are deliberately excluded from CI. Repeated CI execution would invalidate their
role as one-time, unbiased evaluation evidence.

## Hybrid comparison evidence

The `aegisforge hybrid-benchmark` command runs the transparent deterministic semantic
reference provider against the bundled tuning corpus. It writes JSON for automation and
Markdown for review. Only `BLOCK` counts as a malicious prediction; `REVIEW` remains a
separate operational metric. The report also records provider failures and semantic latency.

The reference provider demonstrates the integration and evidence contract. Its synthetic-corpus
measurements are not claims of general production performance.
