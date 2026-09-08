# Contributing to AegisForge

Thank you for helping improve AegisForge. Contributions must preserve its lab-safe scope,
reproducibility, and evidence-first approach.

## Before opening a change

- Use only synthetic data and systems you own or are explicitly authorized to test.
- Do not submit real credentials, personal data, malware, persistence, or destructive payloads.
- Open an issue before proposing a large architectural or behavioral change.
- Keep pull requests focused and explain the security assumption being changed.

## Development setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

On Linux or macOS, activate with `source .venv/bin/activate`.

## Required validation

Run these commands before opening a pull request:

```powershell
python -m ruff check .
python -m pytest -W error
aegisforge benchmark-gate
aegisforge doctor
```

A detection change must include positive, negative, and context-sensitive tests. If a benchmark
corpus informed rule tuning, document that corpus as adapted regression data; do not present it as
an untouched holdout.

## Pull requests

Include:

- the problem and intended outcome;
- the trust boundary or threat scenario affected;
- tests and evaluation evidence;
- safety impact and limitations;
- documentation updates where behavior changes.

Never weaken target validation or tool-authorization boundaries without an explicit security design
discussion.

## Reporting vulnerabilities

Do not open a public issue for a suspected vulnerability. Follow [SECURITY.md](SECURITY.md) and use
GitHub private vulnerability reporting.
