# Security automation

## Dependency audit

The dependency-security workflow installs production dependencies into an isolated virtual
environment and audits them against published vulnerability advisories. It runs for relevant pull
requests and pushes, every Monday, and on manual dispatch.

The audit is blocking: a known vulnerability produces a failed workflow. No advisory identifiers
are silently ignored. Any exception must be documented with applicability, compensating controls,
an owner, and an expiry date before an ignore rule is introduced.

## Dependency maintenance

Dependabot checks Python and GitHub Actions dependencies weekly and proposes reviewable pull
requests. Automated updates must pass the standard test and benchmark quality gates before merge.

## Scope

Dependency auditing complements but does not replace threat modeling, code review, static analysis,
secret scanning, or runtime testing. CodeQL can be enabled when the repository and GitHub plan meet
GitHub code-scanning availability requirements.
