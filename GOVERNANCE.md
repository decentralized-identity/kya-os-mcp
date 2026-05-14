# Governance

## Project Role

This repository is the **DIF TAAWG protocol reference implementation** for MCP-I (Model Context Protocol Identity), the identity surface of KYA-OS (Know Your Agent Operating System). KYA-OS is the umbrella protocol for agent identity, authorization, and observability; MCP-I binds those primitives to Model Context Protocol servers. This repo provides the TypeScript implementation of the MCP-I specification — cryptographic identity, delegation chains, and non-repudiation proofs over MCP.

## Maintainers

| Name        | Email                 | Role               |
| ----------- | --------------------- | ------------------ |
| Dylan Hobbs | dylan.hobbs@vouched.id | Initial Maintainer |

## Decision Making

### Non-Breaking Changes

Non-breaking changes follow a **lazy consensus** model:

- Proposed via pull request
- Approved after 72 hours with no objections from maintainers
- Any maintainer may merge after the waiting period

### Breaking Changes

Breaking changes to the specification require **explicit vote**:

- Labeled with `breaking-change`
- Requires approval from majority of active maintainers
- Minimum 7-day discussion period
- Changes affecting SPEC.md are coordinated with DIF TAAWG

## Relationship to DIF TAAWG

This repository implements the MCP-I specification under development in the **Decentralized Identity Foundation (DIF) Trust and Authorization for AI Working Group (TAAWG)**.

- **Spec decisions** are made in the working group
- **Implementation decisions** are made here
- This repo tracks the authoritative spec as it evolves in TAAWG
- Spec divergences should be reported as issues and resolved with the working group

## Becoming a Maintainer

To become a maintainer:

1. **Sustained contributions** — Demonstrate ongoing commitment through quality PRs, issue triage, and community engagement
2. **DCO compliance** — All contributions must be signed off per the Developer Certificate of Origin
3. **Nomination** — Nominated by an existing maintainer
4. **Approval** — Approved by majority vote of existing maintainers

## Code of Conduct

All participants are expected to follow professional conduct standards. Harassment, discrimination, and disruptive behavior are not tolerated.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
