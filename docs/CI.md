# Continuous integration

The CI workflow runs on pull requests to `main`, pushes to `main`, and manual dispatches.

Each supported Python version executes these controls:

1. Install AegisForge and its development dependencies.
2. Run Ruff static checks.
3. Run the test suite with warnings treated as errors.
4. Generate tuning and adapted-regression benchmark reports.
5. Enforce benchmark precision, recall, F1, and false-positive-rate thresholds.
6. Upload the reports as a 30-day GitHub Actions artifact, including on failed runs.
7. Verify the installed CLI entry point.

Holdout datasets are deliberately excluded from CI. Repeated CI execution would invalidate their
role as one-time, unbiased evaluation evidence.
