/**
 * A recorder and a checkpoint builder whose signer yields no public key, given no `signatures`:
 * they derive a verifier from the Ed25519 did:key the signer names, once the signer shows it signs
 * with that key, and otherwise trust the journal as written, with a warning.
 */
import { exportJWK, generateKeyPair } from 'jose';
import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from 'vitest';
import { logger } from '../../logging/index.js';
import { generateDidKeyFromBytes } from '../../utils/did-helpers.js';
import { base64urlDecodeToBytes } from '../../utils/base64.js';
import { CompactJwsAuditSigner, type AuditSigner } from '../crypto.js';
import { AUDIT_ERROR_CODES } from '../errors.js';
import { MemoryAuditJournal } from '../providers/memory-journal.js';
import type { SignerRef } from '../types.js';
import { ledger } from './observer-fixtures.js';
import { builderWith, insert, record, recorderWith, ref, unsignedEntryAfter } from './stored-entry-fixtures.js';

const WARNED = Symbol.for('@kya-os/mcp/audit-journal-trusted-as-written-warned');

/** A fresh Ed25519 key pair, its private half created non-extractable, and the did:key of its public half. */
async function hiddenKey(): Promise<{ privateKey: CryptoKey; did: string }> {
  const { privateKey, publicKey } = await generateKeyPair('EdDSA', { extractable: true });
  const hidden = await crypto.subtle.importKey('jwk', await exportJWK(privateKey), { name: 'Ed25519' }, false, ['sign']);
  const did = generateDidKeyFromBytes(base64urlDecodeToBytes((await exportJWK(publicKey)).x!));
  return { privateKey: hidden, did };
}

function didKeyRef(did: string): SignerRef {
  return { did, kid: `${did}#${did.slice('did:key:'.length)}`, alg: 'EdDSA' };
}

/** A signer as a remote key service gives one: it signs, and has no `verifier()`. */
function remoteSigner(inner: CompactJwsAuditSigner): AuditSigner & { signs: number } {
  const remote = {
    ref: inner.ref,
    signs: 0,
    sign: async (payload: Uint8Array) => {
      remote.signs += 1;
      return inner.sign(payload);
    },
  };
  return remote;
}

/** A journal holding a genesis and one entry recorded by `signer`, then a forged entry under its name. */
async function journalWithForgery(signer: AuditSigner): Promise<MemoryAuditJournal> {
  const journal = new MemoryAuditJournal();
  await record(recorderWith(journal, signer), 'evt_1', 1);
  await insert(journal, await unsignedEntryAfter((await journal.getHead(ledger))!, { recorder: signer.ref }), '9');
  return journal;
}

const refusal = {
  code: AUDIT_ERROR_CODES.JOURNAL_FAILURE,
  message: 'Audit journal entry is not one its recorder signed',
  details: { sequence: '2' },
};

let warn: MockInstance;
beforeEach(() => {
  delete (globalThis as { [key: symbol]: unknown })[WARNED];
  warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
});
afterEach(() => {
  warn.mockRestore();
  delete (globalThis as { [key: symbol]: unknown })[WARNED];
});

describe('a signer whose key yields no public key, naming the Ed25519 did:key it signs with', () => {
  it('has the recorder and the builder refuse an entry it did not sign, over a non-extractable CryptoKey', async () => {
    const { privateKey, did } = await hiddenKey();
    const signer = new CompactJwsAuditSigner(didKeyRef(did), privateKey);
    await expect(signer.verifier()).resolves.toBeUndefined();
    const journal = await journalWithForgery(signer);

    await expect(record(recorderWith(journal, signer), 'evt_2', 2)).rejects.toMatchObject(refusal);
    await expect(builderWith(journal, signer).createCheckpoint(ledger)).rejects.toMatchObject(refusal);
    expect(warn).not.toHaveBeenCalled();
  });

  it('has them refuse it for a signer with no verifier() at all, as a remote key service gives', async () => {
    const { privateKey, did } = await hiddenKey();
    const signer = remoteSigner(new CompactJwsAuditSigner(didKeyRef(did), privateKey));
    const journal = await journalWithForgery(signer);

    await expect(record(recorderWith(journal, signer), 'evt_2', 2)).rejects.toMatchObject(refusal);
    await expect(builderWith(journal, signer).createCheckpoint(ledger)).rejects.toMatchObject(refusal);
  });

  it('has them build on what another process recorded with the same key, signing the self-check once each', async () => {
    const { privateKey, did } = await hiddenKey();
    const signer = remoteSigner(new CompactJwsAuditSigner(didKeyRef(did), privateKey));
    const journal = new MemoryAuditJournal();
    await record(recorderWith(journal, signer), 'evt_1', 1);

    const before = signer.signs;
    const recorder = recorderWith(journal, signer);
    await expect(record(recorder, 'evt_2', 2)).resolves.toMatchObject({ core: { sequence: '2' } });
    await expect(record(recorder, 'evt_3', 3)).resolves.toMatchObject({ core: { sequence: '3' } });
    // One self-check, then one receipt for each entry.
    expect(signer.signs - before).toBe(3);
    await expect(builderWith(journal, signer).createCheckpoint(ledger)).resolves.toMatchObject({ core: { treeSize: '4' } });
  });
});

describe('a signer whose key yields no public key, and names no did:key it signs with', () => {
  it('has them trust the journal as written, as before, and warns once', async () => {
    const { privateKey } = await hiddenKey();
    const cases: AuditSigner[] = [
      // The did:key of another key than the one it signs with: its self-check does not verify.
      new CompactJwsAuditSigner(didKeyRef((await hiddenKey()).did), privateKey),
      // A DID that is no Ed25519 did:key.
      new CompactJwsAuditSigner(ref(), privateKey),
      // An ES256 signer: only an Ed25519 did:key is decoded.
      remoteSigner(new CompactJwsAuditSigner(
        { ...didKeyRef((await hiddenKey()).did), alg: 'ES256' },
        (await generateKeyPair('ES256', { extractable: false })).privateKey,
      )),
    ];
    for (const signer of cases) {
      const journal = await journalWithForgery(signer);
      await expect(record(recorderWith(journal, signer), 'evt_2', 2)).resolves.toMatchObject({ core: { sequence: '3' } });
      await expect(builderWith(journal, signer).createCheckpoint(ledger)).resolves.toMatchObject({ core: { treeSize: '4' } });
    }
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn.mock.calls[0]![0]).toMatch(/^\[kya-os\] An audit recorder or checkpoint builder trusts its journal as written/);
  });

  it('fails as the signer fails, and is checked again next time, when the signer cannot sign the self-check', async () => {
    const { privateKey, did } = await hiddenKey();
    const inner = new CompactJwsAuditSigner(didKeyRef(did), privateKey);
    let fail = true;
    const signer: AuditSigner = {
      ref: inner.ref,
      sign: async (payload) => {
        if (fail) throw new Error('key service unavailable');
        return inner.sign(payload);
      },
    };
    const journal = new MemoryAuditJournal();
    fail = false;
    await record(recorderWith(journal, inner), 'evt_1', 1);
    const recorder = recorderWith(journal, signer);
    fail = true;
    await expect(record(recorder, 'evt_2', 2)).rejects.toThrow('key service unavailable');
    fail = false;
    await expect(record(recorder, 'evt_2', 2)).resolves.toMatchObject({ core: { sequence: '2' } });
  });
});
