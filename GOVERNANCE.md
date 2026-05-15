# Governance

## Project Role

This repository is the **DIF TAAWG protocol reference implementation** for the KYA-OS (Know Your Agent Operating System) protocol's MCP binding. KYA-OS is the agent identity, authorization, and observability protocol; this repo provides the TypeScript implementation of its MCP binding — cryptographic identity, delegation chains, and non-repudiation proofs over Model Context Protocol. The wire format is specified in [`SPEC.md`](./SPEC.md) (the KYA-OS specification, version 1.0.0).

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

This repository implements the KYA-OS specification, donated to the **Decentralized Identity Foundation (DIF) Trust and Authorization for AI Working Group (TAAWG)** and under review there for ratification as a DIF standard.

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
