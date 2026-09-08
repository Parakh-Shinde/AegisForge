# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 0.8.x | Yes |
| Earlier releases | No |

## Reporting a vulnerability

Use GitHub's **private vulnerability reporting** for suspected vulnerabilities. Please include:

- the affected version and component;
- a minimal reproduction using synthetic data;
- expected and observed behavior;
- security impact and suggested mitigation, if known.

Do not open a public issue, include real credentials or personal data, or publish destructive
proof-of-concept payloads. You should receive an initial acknowledgement within seven days.

## Authorized use

AegisForge is intended only for isolated environments you own or are explicitly authorized to test.
Do not point it at public systems. The default target policy permits loopback destinations only;
private container ranges require explicit opt-in.

Security research contributions must preserve the tool-authorization boundary: model-generated text
is evidence, never authority to execute a tool.
