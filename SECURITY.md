# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |
| 0.x     | No        |

## Reporting a Vulnerability

Please do **not** open a public GitHub issue for security vulnerabilities.

Report issues privately to: **dylan.hobbs@vouched.id**

Include in your report:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

**Response timeline:**
- Acknowledgement within 48 hours
- Triage and severity assessment within 7 days
- Coordinated disclosure after 90 days (or sooner if a fix is ready)

Reporters will be credited in release notes unless they prefer to remain anonymous.

## Scope

This policy covers the `@kya-os/mcp` npm package and this repository. It includes:
- Cryptographic implementation errors (Ed25519, JWS, SHA-256)
- Delegation verification bypasses
- Session replay vulnerabilities
- DID resolution attacks

## Out of Scope

- Vulnerabilities in dependencies (report to the respective maintainers)
- Issues requiring physical access to the host
