/**
 * Whoever presents a re-delegation chooses the `parentId` the host's chain resolver is asked about,
 * and holds no key until the presented credential verifies. So a refusal tells the presenter only
 * what the presented credential states: what the resolver answered, an ancestor's id, subject or
 * issuer, goes to the operator's log. And the presented credential is verified before any ancestor,
 * so a presenter who cannot sign as the parent's subject learns nothing of an ancestor's standing
 * and costs no ancestor's verification.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { logger } from "../../logging/index.js";
import { validateDelegationChain, type DelegationCredentialVerifierPort } from "../chain-enforcement.js";
import type { DelegationCredential } from "../../types/protocol.js";
import { SERVER, chainOfThree, cred, resolving } from "./helpers/chain-fixtures.js";

afterEach(() => {
  vi.restoreAllMocks();
});

/** What the operator's log was told while `run` ran, line by line and as one text, with what `run` answered. */
async function logged<T>(run: () => Promise<T>): Promise<{ answer: T; log: string; lines: string[] }> {
  const warn = vi.spyOn(logger, "warn").mockImplementation(() => undefined);
  const answer = await run();
  const lines = warn.mock.calls.map((call) => call.map(String).join(" "));
  return { answer, log: lines.join("\n"), lines };
}

const { root, middle, leaf } = chainOfThree();

/** A presented leaf under `middle` that `issuerDid` claims, and the credential names as its issuer. */
const presented = (issuerDid: string, parentId = "middle", issuer = issuerDid): DelegationCredential => ({
  ...cred({ id: "forged", issuerDid, subjectDid: "did:presenter", parentId, scopes: ["read"], audience: SERVER }),
  issuer,
});

describe("validateDelegationChain: a refusal of how the presented credential links to its parent", () => {
  it.each([
    [
      "names an issuerDid that is not the parent's subject",
      presented("did:presenter"),
      'Delegation "forged" issued by "did:presenter" is not a re-delegation by the subject of parent "middle"',
      "parent subject is did:sub",
    ],
    [
      "is signed by another than the parent's subject",
      presented("did:sub", "middle", "did:presenter"),
      'Delegation "forged" is signed by "did:presenter", not by the subject of parent "middle"',
      "parent subject is did:sub",
    ],
    [
      "is in a credential that names no issuer",
      { ...presented("did:sub"), issuer: { name: "no id" } as unknown as string },
      'Delegation "forged" is signed by an unidentified issuer, not by the subject of parent "middle"',
      "is signed by an unidentified issuer but parent subject is did:sub",
    ],
    [
      "names a parent the resolved chain does not end with",
      presented("did:sub", "elsewhere"),
      'Delegation "forged" references parent "elsewhere", which its resolved chain does not end with',
      "expected middle",
    ],
  ])("names nothing the resolver answered when it %s, and logs what it withheld", async (_name, forged, reason, withheld) => {
    const { answer, log } = await logged(() => validateDelegationChain(forged, resolving([root, middle])));
    expect(answer).toEqual({ valid: false, reason, code: "chain_invalid", transient: false });
    expect(log).toContain(withheld);
  });
});

describe("validateDelegationChain: a refusal of the resolved ancestors themselves", () => {
  it.each([
    ["two ancestors that do not link", [cred({ id: "root", issuerDid: "did:user", subjectDid: "did:other", scopes: ["read"] }), middle], "did:other"],
    ["an ancestor repeated", [root, root, middle], "circular reference"],
    ["a root that names a parent", [cred({ id: "root", issuerDid: "did:user", subjectDid: "did:agent", parentId: "older", scopes: ["read"] }), middle], "older"],
  ])("tells the presenter only that its chain is broken when the resolver returned %s", async (_name, ancestors, detail) => {
    const { answer, log } = await logged(() => validateDelegationChain(leaf, resolving(ancestors)));
    expect(answer).toEqual({
      valid: false,
      reason: 'Delegation "leaf" does not descend from a root through the chain its parent resolves to',
      code: "chain_invalid",
      transient: false,
    });
    expect(log).toContain(detail);
  });

  it("names neither a resolved root nor its issuer when that issuer is not trusted", async () => {
    const { answer, log } = await logged(() =>
      validateDelegationChain(leaf, { ...resolving([root, middle]), trustedRootIssuers: ["did:trusted"] }),
    );
    expect(answer).toEqual({
      valid: false,
      reason: 'Delegation "leaf" descends from a root whose issuer is not a trusted root issuer',
      code: "untrusted_root",
      transient: false,
    });
    expect(log).toContain('Root delegation root is issued by "did:user", which is not a trusted root issuer');
  });

  it("still names the presented root and its issuer, which the presenter wrote", async () => {
    const answer = await validateDelegationChain(root, { ...resolving([]), trustedRootIssuers: ["did:trusted"] });
    expect(answer.reason).toBe('Root delegation root is issued by "did:user", which is not a trusted root issuer');
  });
});

describe("validateDelegationChain: the presented credential is verified before its ancestors", () => {
  /** A verifier that records each credential it is asked about, and refuses `refused`. */
  const recording = (refused?: DelegationCredential) => {
    const asked: string[] = [];
    const verifier: DelegationCredentialVerifierPort = {
      verifyDelegationCredential: async (credential) => {
        asked.push(credential.credentialSubject.delegation.id);
        return credential === refused ? { valid: false, reason: "Signature verification failed" } : { valid: true };
      },
    };
    return { asked, verifier };
  };

  it("verifies it first, then each ancestor root first, and reports them root first", async () => {
    const { asked, verifier } = recording();
    const result = await validateDelegationChain(leaf, { ...resolving([root, middle]), verifier });
    expect(result.valid).toBe(true);
    expect(asked).toEqual(["leaf", "root", "middle"]);
    expect(result.evaluated).toEqual([root, middle, leaf]);
  });

  it("verifies no ancestor, and reports it alone, when it does not verify", async () => {
    const { asked, verifier } = recording(leaf);
    const result = await validateDelegationChain(leaf, { ...resolving([root, middle]), verifier });
    expect(result).toMatchObject({ valid: false, reason: "Delegation leaf invalid: Signature verification failed" });
    expect(asked).toEqual(["leaf"]);
    expect(result.evaluated).toEqual([leaf]);
  });

  it("reports the ancestors up to the one refused, then itself, when an ancestor does not verify", async () => {
    const { asked, verifier } = recording(middle);
    const result = await validateDelegationChain(leaf, { ...resolving([root, middle]), verifier });
    expect(result).toMatchObject({ valid: false, reason: "Delegation middle invalid: Signature verification failed" });
    expect(asked).toEqual(["leaf", "root", "middle"]);
    expect(result.evaluated).toEqual([root, middle, leaf]);
  });
});

describe("validateDelegationChain: presenter text in the operator's log", () => {
  const INJECTED = "forged\n[kya-os] audit: delegation approved by admin";
  /** No line break, bidirectional override or other character that rewrites the log as it is read. */
  const REWRITES_THE_LOG = /[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/;

  it("quotes the presented id and parentId, and writes the log line free of what they hold", async () => {
    const forged: DelegationCredential = {
      ...cred({ id: INJECTED, issuerDid: "did:sub", subjectDid: "did:presenter", parentId: "elsewhere\u202e", scopes: ["read"], audience: SERVER }),
      issuer: "did:sub",
    };
    const { answer, log, lines } = await logged(() => validateDelegationChain(forged, resolving([root, middle])));
    expect(answer.reason).toBe(
      'Delegation "forged\\n[kya-os] audit: delegation approved by admin" references parent "elsewhere\\u202e", ' +
        "which its resolved chain does not end with",
    );
    expect(lines.length).toBeGreaterThan(0);
    for (const line of lines) expect(line).not.toMatch(REWRITES_THE_LOG);
    expect(log).toContain("expected middle");
  });

  it("quotes the presented id when its ancestors are broken, or descend from an untrusted root", async () => {
    const presentedLeaf: DelegationCredential = {
      ...cred({ id: INJECTED, issuerDid: "did:sub", subjectDid: "did:presenter", parentId: "middle", scopes: ["read"], audience: SERVER }),
      issuer: "did:sub",
    };
    const broken = await logged(() => validateDelegationChain(presentedLeaf, resolving([root, root, middle])));
    expect(broken.answer.reason).toBe(
      'Delegation "forged\\n[kya-os] audit: delegation approved by admin" does not descend from a root through the chain its parent resolves to',
    );
    expect(broken.lines.length).toBeGreaterThan(0);
    for (const line of broken.lines) expect(line).not.toMatch(REWRITES_THE_LOG);

    const untrusted = await logged(() =>
      validateDelegationChain(presentedLeaf, { ...resolving([root, middle]), trustedRootIssuers: ["did:trusted"] }),
    );
    expect(untrusted.answer.reason).toBe(
      'Delegation "forged\\n[kya-os] audit: delegation approved by admin" descends from a root whose issuer is not a trusted root issuer',
    );
    expect(untrusted.lines.length).toBeGreaterThan(0);
    for (const line of untrusted.lines) expect(line).not.toMatch(REWRITES_THE_LOG);
  });

  it("quotes the presented id and parentId when the resolver answers no chain at all", async () => {
    const forged: DelegationCredential = {
      ...cred({ id: INJECTED, issuerDid: "did:sub", subjectDid: "did:presenter", parentId: "elsewhere\u202e", scopes: ["read"], audience: SERVER }),
      issuer: "did:sub",
    };
    const { answer } = await logged(() => validateDelegationChain(forged, resolving([])));
    expect(answer).toMatchObject({ valid: false, code: "chain_invalid" });
    expect(answer.reason).toBe(
      'Delegation "forged\\n[kya-os] audit: delegation approved by admin" references parent "elsewhere\\u202e" ' +
        "but the resolved chain is empty",
    );
    expect(answer.reason).not.toMatch(REWRITES_THE_LOG);
  });
});
