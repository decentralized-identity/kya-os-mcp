# Upgrading @kya-os/mcp

This file holds the detail behind the Upgrading entries in CHANGELOG.md: the steps for each setup, the limits, and the tables of changed refusal reasons.
Each release has one section, newest first, and declares every change of behaviour against the release before it.
CHANGELOG.md says what changed and names the section here that says what to do about it.

## From 1.22.0

### Signing keys and `assertionMethod`

A delegation credential, a status list and a delegation hop verify only under a key their issuer's own DID document lists under `assertionMethod` (SPEC.md §6.2, §6.10, §11.5).
A key the document lists only under another relationship, such as `authentication`, or under none, no longer verifies one.
Update issuers before verifiers upgrade.

What each setup has to do:

| Setup | Action |
| --- | --- |
| did:key issuers | None. A did:key document lists its key under `assertionMethod`. |
| did:web documents built with `buildDidWebDocument` | None. Every key is listed under `assertionMethod`. |
| `signDelegationCredential` and `signStatusListCredential` | None. Each states `proofPurpose: "assertionMethod"` and names its key. |
| A `VCSigningFunction` you give `DelegationCredentialIssuer` or `StatusList2021Manager` | The proof it returns names the signing key in `verificationMethod`, and a `proofPurpose` it states is `assertionMethod`. |
| Hand-written did:web documents | List each signing key under `assertionMethod`, as below. |
| did:cheqd documents made with `@cheqd/sdk` before 5.3.3 | They list keys only under `authentication`. Update the DID as `src/integrations/cheqd/README.md` shows. |

An issuer whose documents or credentials do not yet comply must:

1. List each signing key under `assertionMethod` of its own DID document, by reference or embedded.
   The method is defined once, has an id under the issuer's DID and a `type`, and names the issuer's DID as its `controller`.
2. Set each proof's `proofPurpose` to `assertionMethod`.
   Only the legacy proof profile of SPEC.md §6.2 permits an omitted purpose; the Card `eddsa-jcs-2022` profile requires it.
3. Name the signing key with a non-empty `kid` or `proof.verificationMethod`.
   A VC-JWT with no `kid`, or a status list read by `CheqdStatusListResolver` with no `verificationMethod`, is checked only with the first `assertionMethod` entry.
   Card `eddsa-jcs-2022` proofs must name their key.

### Issuer identifiers

A credential names its issuer, in `issuer`, in an issuer object's `id` and in a VC-JWT's `iss`, by a URL as written (SPEC.md §6.2).
A value with white space at either end, or with a control or format character, U+2028, U+2029 or a lone surrogate anywhere, is refused before any DID is resolved.

### Delegations the gate cannot encode

The delegation gate refuses, as `delegation_invalid`, a delegation holding a value RFC 8785 cannot encode.
In 1.22.0 such a call threw a `TypeError` or ran the tool.
Issue no delegation that holds one.

### Changed refusal reasons

A refusal reason is text for people, and its wording changed where it quotes a value the other party chose.
`"<v>"` quotes a value as a JSON string of at most its first 64 characters, with `...` after it when cut, and with control and hidden characters, quote marks, backslashes and lone surrogates escaped.
A value that is not a string reads `of type <type>`.
Code that matches on reason text needs the new wording.

| 1.22.0 | Now |
| --- | --- |
| `Verification method <id> not found`, `Verification method <kid> not found in DID Document`, `Issuer DID document has no verification method matching "<id>"` | `Verification method "<id>" not found under assertionMethod of "<issuer>"` |
| `DID Document has no verification method`, `Issuer DID document has no verification method matching "(any)"` | `JWT kid is absent, and assertionMethod of "<issuer>" has no usable first entry`, or the same starting `Status list proof verificationMethod is absent` |
| `Proof missing verificationMethod` for `""`, `null` or `0`, `Verification method 42 not found`; an empty `kid`, or a list `verificationMethod` that is empty or not a string, read as none | `Proof verificationMethod "<v>" is not a DID URL`, `JWT kid "" is not a DID URL`, `Status list proof verificationMethod "<v>" is not a DID URL` |
| none: the key verified | `Verification method "<id>" under assertionMethod of "<issuer>" has another DID as its controller: "<did>"`, or `as its document's id: "<did>"` |
| none: the proof verified | `Proof purpose "<v>" is not assertionMethod` |
| `Could not resolve issuer DID: <issuer>`; for a VC-JWT `iss` that is not a string, ``Credential `issuer` does not match the JWT `iss` (the verified signer)`` | `Credential issuer "<v>" is not a URL`, `Credential issuer id "<v>" is not a URL`, `JWT iss "<v>" is not a URL` |
| a `TypeError`, or the tool ran | `Delegation credential holds a value that cannot be encoded as RFC 8785 text` |
| `Delegation status is revoked`, `Unsupported credential proof.type: <type>`, `Could not resolve issuer DID: <issuer>`, `Could not resolve issuer DID <issuer>: <error>`, `Credential revoked via <type> (<purpose>)`, `credentialSubject contains non-delegation field(s): <a>, <b>`, `Status list fetch failed: HTTP <status> for <url>`, `Revocation check failed for delegation <id>: <error>`, `Delegation <id> is revoked via ancestor <id>`, `Delegation <id> is revoked: <reason>` | the same with each value quoted, as in `Delegation status is "revoked"` and `credentialSubject contains non-delegation field(s): "<a>, <b>"` |
| `Status list issuer "<issuer>" is not the expected issuer "<issuer>"` and `status list statusPurpose mismatch`, values as written | the same with each value quoted |
| `status list has no statusPurpose (expected "<purpose>")`, an em dash and `fail-closed` | `status list has no statusPurpose (expected "<purpose>") - fail-closed` |
| the `<error>` or `<reason>` in `Status check error`, `Signature verification error`, `Could not resolve issuer DID`, `JWT envelope signature is not valid`, `Failed to resolve delegation chain`, `Revocation check failed` and `Delegation <id> is revoked`, as written | cut after 256 UTF-16 code units and marked with U+2026, with control and hidden characters and lone surrogates read as U+FFFD |
