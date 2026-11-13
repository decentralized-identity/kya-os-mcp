/**
 * What a proof keeps while it waits to be sent.
 *
 * A wrapper leaves its proof with the middleware until the transport sends
 * the result. A result that is never sent, as when the client cancels the
 * call, leaves its proof waiting until it expires, and the waiting proofs are
 * bounded by a count and by a budget over what each one holds. The budget
 * counts the proof's claims and its audit context. This test holds it to
 * that on a server that records long chains: the digest of every credential
 * of a call belongs to the call's audit events, and a waiting proof keeps
 * none of them.
 *
 * What is kept is read from a snapshot of the heap, which holds every value
 * still reachable and nothing else, so the answer does not turn on how the
 * heap happens to grow.
 */
import v8 from 'node:v8';
import { describe, expect, it, vi } from 'vitest';
import type { Digest } from '../../audit/types.js';
import { PENDING_PROOF_META_KEY } from '../with-kya-os.session.js';
import { CONSENT, TOOL, released } from './helpers/delegated-call.js';
import { delegate, party } from './helpers/delegating-party.js';
import { connectTransport, createMiddleware } from './helpers/received-proof.js';

/** The most credential digests an audit event lists (`delegationChainDigests`). */
const LISTED = 256;

/** What every digest the describer lists starts with, after `sha256:`. */
const MARK = 'feedfacecafe';

/**
 * How many of the digests the describer listed are reachable now. A heap
 * snapshot is taken after a full collection, and lists every string that is
 * still reachable, with its text.
 */
async function digestsStillHeld(): Promise<number> {
  const listed = new RegExp(`sha256:${MARK}[0-9a-f]{${64 - MARK.length}}`, 'g');
  const found = new Set<string>();
  let carried = '';
  for await (const chunk of v8.getHeapSnapshot()) {
    const text = carried + String(chunk);
    for (const [digest] of text.matchAll(listed)) found.add(digest);
    // A digest split across two chunks is found whole in the next one.
    carried = text.slice(-80);
  }
  return found.size;
}

const described = vi.hoisted(() => ({ presentations: 0 }));

// The describer as it is, with every presentation recorded as the chain of
// 256 credentials it would be at the bound: each digest a string of its own,
// as a digest computed for the call is, and each written so that it can be
// told apart from any other string in the heap. Each is joined into one flat
// string, which a heap snapshot shows with its text: one built with `+` or a
// template is shown there as the parts it was built from.
vi.mock('../with-kya-os.delegation-records.js', async (importOriginal) => {
  const { tappedRecords } = await import('./helpers/describer-tap.js');
  return tappedRecords(await importOriginal<typeof import('../with-kya-os.delegation-records.js')>(), (records) => {
    const first = (described.presentations += 1) * LISTED;
    const delegationChainDigests = Array.from(
      { length: LISTED },
      (_, hop) => ['sha256:', MARK, (first + hop).toString(16).padStart(64 - MARK.length, '0')].join('') as Digest,
    );
    return { ...records, chainEvidence: { delegationChainDigests } };
  });
});

describe('a proof that waits to be sent', () => {
  it('keeps none of the per-credential digests of its call, however long the chain', async () => {
    const listed: number[] = [];
    // The last list recorded, held here so the count is seen to find one.
    let lastListed: readonly Digest[] | undefined;
    const kyaos = await createMiddleware({
      autoSession: true,
      audit: {
        record: async (event) => {
          const digests = event.authorization?.delegationChainDigests;
          if (digests !== undefined) {
            listed.push(digests.length);
            lastListed = digests;
          }
          return { status: 'pending', event: event as never };
        },
      },
    });
    // A transport is open and nothing is sent through it: every proof waits.
    await connectTransport(kyaos);
    const [user, agent] = await Promise.all([party(), party()]);
    const credential = await delegate(user, agent.did, { id: 'del-waiting' });
    const handler = kyaos.wrapWithDelegation(TOOL, CONSENT, kyaos.wrapWithProof(TOOL, released));

    // Delegated calls whose results are never sent, each recorded with the
    // digests of 256 credentials.
    const calls = 40;
    const waiting: Array<Record<string, unknown>> = [];
    for (let call = 0; call < calls; call += 1) {
      const result = await handler({ recordId: `r-${call}`, _kyaos_delegation: credential });
      expect(result.isError).toBeUndefined();
      waiting.push(result);
    }

    // The lists were recorded, with the verdict on each call...
    expect(listed).toEqual(Array.from({ length: calls }, () => LISTED));
    // ...and while every proof still waits, with its result held here, the
    // only digests left in the heap are the list this test holds.
    for (const result of waiting) {
      expect((result._meta as Record<string, unknown>)[PENDING_PROOF_META_KEY]).toEqual(expect.any(String));
    }
    expect(await digestsStillHeld()).toBe(LISTED);
    expect(lastListed).toHaveLength(LISTED);
    lastListed = undefined;
    expect(await digestsStillHeld()).toBe(0);
  }, 120_000);
});
