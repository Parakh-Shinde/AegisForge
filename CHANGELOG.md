# Changelog

All notable changes to AegisForge are documented in this file.

## [0.10.0] - 2026-09-13

### Added

- Bounded defensive-context classification for educational and incident-response prompts.
- Compositional override, indirect instruction, delegation, fragmentation, and persistence detection.
- Covert exfiltration, credential-access, tool-abuse, framing, and multilingual evidence.
- Adapted holdout-v2 regression corpus with distinct case identifiers and classification.
- Rule-only and hybrid regression thresholds covering all 24 adapted cases.
- `v010-regression-gate` CLI command and versioned JSON/Markdown CI evidence.

### Evaluation

The immutable holdout-v2 first-run result remains the independent v0.9 evidence.
After error analysis and detector revision, all 24 derived cases pass as explicitly
labeled adapted regression data with precision, recall, and F1 of `1.0000`, zero
false positives, zero false negatives, and zero provider failures. These results
must not be represented as fresh holdout or production performance.

### Security

- Defensive exemptions are bounded and covered by adversarial negative tests.
- Semantic evidence remains non-authorizing for tool execution.
- Corpus-size and metric gates prevent silent case removal or known-error regression.
- CI never reruns the preserved holdout-v2 evaluation.

## [0.9.0] - 2026-09-10

### Added

- Provider-independent semantic detector contract with sanitized failure evidence.
- Deterministic hybrid allow, review, and block policy.
- Auditable hybrid decision telemetry and stable JSON serialization.
- Transparent deterministic semantic reference provider.
- Rule-only versus hybrid comparison benchmark and CLI reports.
- Machine-verifiable pre-holdout freeze with cross-platform SHA-256 checks.
- Balanced 24-case holdout-v2 corpus and guarded one-time evaluation command.
- Preserved holdout-v2 first-run evidence and documented error analysis.

### Evaluation

The fresh holdout-v2 first run produced F1 `0.1333` for both rule-only and hybrid
modes. The reference semantic provider produced no classification improvement.
The complete report is preserved without tuning v0.9 against its failures.

### Security

- Semantic evidence never authorizes tool execution.
- Expected provider failures are converted to sanitized unavailable evidence.
- Holdout execution stops if a frozen detector fingerprint changes.
- Holdout datasets remain excluded from recurring CI evaluation.

## [0.8.0] - 2026-09-08

- Added independent evaluation provenance, benchmark quality gates, CI evidence
  artifacts, dependency auditing, CodeQL, and the first immutable holdout protocol.

## [0.7.0] - 2026-09-06

- Added prompt normalization, context-aware classification, and expanded evasion coverage.

## [0.6.2] - 2026-09-05

- Established the clean, tested Git baseline for the public repository.
