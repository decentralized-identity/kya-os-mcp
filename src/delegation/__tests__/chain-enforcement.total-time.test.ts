/**
 * `validateDelegationChain` puts no limit on a chain's length unless the host sets
 * `maxChainLength`, so what bounds its time is a budget for the whole check: `totalTimeoutMs`, 30
 * seconds by default. The chain resolver, each credential's verification and each revocation
 * answer wait inside it, each under its own `dependencyTimeoutMs` too. A check out of time is
 * refused as `deadline_exceeded`, which is transient, and asks nothing more, so dependencies that
 * each answer just inside their own deadline cannot hold it open between them. The clock is faked.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { REFUSED_TIMEOUTS, settledAfter, timeoutTypeError } from "../../__tests__/utils/deadlines.js";
import { validateDelegationChain, type ChainEnforcementDeps } from "../chain-enforcement.js";
import { baseDeps, linkedChain } from "./helpers/chain-fixtures.js";

afterEach(() => {
  vi.useRealTimers();
});

const HOPS = 12;
const OUT_OF_TIME = "the delegation check did not finish within 30 seconds";
/** A dependency that answers `value` after `ms`, counting how often it is asked. */
const slow = <T>(ms: number, value: T) => vi.fn(() => new Promise<T>((resolve) => setTimeout(() => resolve(value), ms)));

/** The check of a chain of `HOPS` credentials, presented by its leaf, with `deps`. */
const checking = (deps: Partial<ChainEnforcementDeps>) => {
  const chain = linkedChain(HOPS);
  return settledAfter(() => validateDelegationChain(chain[HOPS - 1]!, { ...baseDeps, resolveDelegationChain: async () => chain, ...deps }));
};

describe("the time validateDelegationChain may take in all", () => {
  it("accepts a chain of any length when its dependencies answer, with no option set", async () => {
    const chain = linkedChain(60);
    expect(await validateDelegationChain(chain[59]!, { ...baseDeps, resolveDelegationChain: async () => chain })).toMatchObject({ valid: true });
  });

  it("is 30 seconds by default: verifications that each answer in 4 end the check there, and nothing more is asked", async () => {
    const verifyDelegationCredential = slow(4_000, { valid: true });
    const { value, ms } = await checking({ verifier: { verifyDelegationCredential } });
    expect(value).toMatchObject({ valid: false, code: "deadline_exceeded", transient: true });
    expect(value.reason).toContain(OUT_OF_TIME);
    expect(ms).toBe(30_000);
    expect(verifyDelegationCredential).toHaveBeenCalledTimes(8);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(verifyDelegationCredential).toHaveBeenCalledTimes(8);
  });

  it("covers the revocation answers with the verifications before them", async () => {
    const verifyDelegationCredential = slow(2_000, { valid: true });
    const isRevoked = slow(2_500, { revoked: false });
    const { value, ms } = await checking({ verifier: { verifyDelegationCredential }, revocationChecker: { isRevoked } });
    expect(value).toMatchObject({ valid: false, code: "deadline_exceeded", transient: true });
    expect(value.reason).toBe(`Revocation check failed for delegation "c2": ${OUT_OF_TIME}`);
    expect(ms).toBe(30_000);
    expect(verifyDelegationCredential).toHaveBeenCalledTimes(HOPS);
    expect(isRevoked).toHaveBeenCalledTimes(3);
  });

  it("covers the chain resolver's answer too", async () => {
    const chain = linkedChain(HOPS);
    const verifyDelegationCredential = slow(4_000, { valid: true });
    const { value, ms } = await checking({ resolveDelegationChain: slow(4_500, chain), verifier: { verifyDelegationCredential } });
    expect(value).toMatchObject({ valid: false, code: "deadline_exceeded" });
    expect(ms).toBe(30_000);
    expect(verifyDelegationCredential).toHaveBeenCalledTimes(7);
  });

  it("is the totalTimeoutMs the host sets: raised, the same chain passes; lowered, it ends sooner", async () => {
    const raised = await checking({ verifier: { verifyDelegationCredential: slow(4_000, { valid: true }) }, totalTimeoutMs: 60_000 });
    expect(raised.value).toMatchObject({ valid: true });
    expect(raised.ms).toBe(HOPS * 4_000);
    vi.useRealTimers();
    const lowered = await checking({ verifier: { verifyDelegationCredential: slow(4_000, { valid: true }) }, totalTimeoutMs: 9_000 });
    expect(lowered.value).toMatchObject({ valid: false, code: "deadline_exceeded" });
    expect(lowered.value.reason).toContain("the delegation check did not finish within 9 seconds");
    expect(lowered.ms).toBe(9_000);
  });

  it("still gives each dependency its own deadline inside it", async () => {
    const { value, ms } = await checking({ verifier: { verifyDelegationCredential: () => new Promise<never>(() => undefined) } });
    expect(value).toMatchObject({ valid: false, code: "deadline_exceeded" });
    expect(value.reason).toContain("the credential verifier did not answer within 5 seconds");
    expect(ms).toBe(5_000);
  });

  it.each(REFUSED_TIMEOUTS)("refuses every chain, asking nothing, for a totalTimeoutMs of %s", async (_label, totalTimeoutMs, got) => {
    const asked = vi.fn();
    const chain = linkedChain(2);
    expect(
      await validateDelegationChain(chain[1]!, {
        ...baseDeps,
        verifier: { verifyDelegationCredential: asked },
        resolveDelegationChain: asked,
        revocationChecker: { isRevoked: asked },
        totalTimeoutMs: totalTimeoutMs as number,
      }),
    ).toEqual({
      valid: false,
      reason: timeoutTypeError(got, "", "totalTimeoutMs").message.slice("[kya-os] ".length),
      code: "configuration_error",
      transient: false,
    });
    expect(asked).not.toHaveBeenCalled();
  });
});
