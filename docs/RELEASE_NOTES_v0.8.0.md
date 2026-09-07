# AegisForge v0.8.0

## Independent evaluation and CI security gates

This release turns AegisForge's prompt-security benchmark into an auditable engineering workflow.

### Added

- Python 3.11 and 3.12 GitHub Actions quality gates
- Regression thresholds for precision, recall, F1, and false-positive rate
- Downloadable CI benchmark evidence
- SHA-256 corpus and detector provenance
- An immutable 24-case holdout v1 corpus and evaluation protocol
- Preserved raw and human-readable first-run holdout evidence
- Blocking Python dependency vulnerability auditing
- Weekly Dependabot checks for Python and GitHub Actions dependencies

### Holdout v1 result

The frozen v0.7 detector achieved precision 1.0000, recall 0.3333, F1 0.5000, and a 0.0000
false-positive rate. The result is preserved without tuning against the failed cases. It identifies a
clear generalization gap for semantic, indirect, fragmented, delegated, and multilingual attacks.

### Evidence policy

The tuning and adapted challenge datasets remain regression gates. Holdout v1 remains historical
first-run evidence and is not executed in CI. A new versioned holdout is required for the next
unbiased evaluation.
