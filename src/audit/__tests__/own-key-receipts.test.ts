import { generateKeyPairSync, type KeyObject } from 'node:crypto';
import { exportJWK, generateKeyPair, type JWK } from 'jose';
import { describe, expect, it, vi } from 'vitest';
import {
  CompactJwsAuditSignatureVerifier,
  CompactJwsAuditSigner,
  type AuditSignatureVerifier,
  type AuditSigner,
} from '../crypto.js';
import { AUDIT_ERROR_CODES } from '../errors.js';
import { publicJwkOf } from '../own-key.js';
import { MemoryAuditJournal } from '../providers/memory-journal.js';
import { ledger } from './observer-fixtures.js';
import {
  builderWith,
  insert,
  jwkSigner,
  record,
  recorderWith,
  ref,
  unsignedEntryAfter,
} from './stored-entry-fixtures.js';

const payload = new TextEncoder().encode('{"receipt":1}');

/** The same kind of Ed25519 private key in each form the signer takes that yields its public key. */
async function privateKeyForms(): Promise<Record<string, CryptoKey | JWK | KeyObject>> {
  const { privateKey } = await generateKeyPair('EdDSA', { extractable: true });
  return {
    'extractable CryptoKey': privateKey,
    'private JWK': await exportJWK((await generateKeyPair('EdDSA', { extractable: true })).privateKey),
    KeyObject: generateKeyPairSync('ed25519').privateKey,
  };
}

/** A journal holding a genesis and one entry recorded by `signer`, then a forged entry under its name. */
async function journalWithForgery(signer: AuditSigner): Promise<MemoryAuditJournal> {
  const journal = new MemoryAuditJournal();
  await record(recorderWith(journal, signer), 'evt_1', 1);
  await insert(journal, await unsignedEntryAfter((await journal.getHead(ledger))!, { recorder: signer.ref }), '9');
  return journal;
}

describe('CompactJwsAuditSigner: a verifier of its own signatures', () => {
  it('is derived from a private JWK, a KeyObject or an extractable CryptoKey', async () => {
    for (const [form, key] of Object.entries(await privateKeyForms())) {
      const signer = new CompactJwsAuditSigner(ref(), key);
      const verifier = await signer.verifier();
      expect(verifier, form).toBeDefined();
      const jws = await signer.sign(payload);
      await expect(verifier!.verify(payload, jws, ref()), form).resolves.toBe(true);
      await expect(verifier!.verify(new TextEncoder().encode('{"receipt":2}'), jws, ref()), form).resolves.toBe(false);
      const other = await jwkSigner();
      await expect(verifier!.verify(payload, await other.sign(payload), ref()), form).resolves.toBe(false);
    }
  });

  it('verifies only under its own key reference', async () => {
    const signer = await jwkSigner();
    const verifier = (await signer.verifier())!;
    const jws = await signer.sign(payload);
    for (const other of [ref('key-2'), { ...ref(), did: 'did:key:zOther' }, ref('key-1', 'ES256')]) {
      await expect(verifier.verify(payload, jws, other)).resolves.toBe(false);
    }
  });

  it('verifies an ES256 signer from its P-256 key', async () => {
    const { privateKey } = await generateKeyPair('ES256', { extractable: true });
    const signer = new CompactJwsAuditSigner(ref('p256', 'ES256'), privateKey);
    const verifier = (await signer.verifier())!;
    await expect(verifier.verify(payload, await signer.sign(payload), ref('p256', 'ES256'))).resolves.toBe(true);
  });

  it('is not derived from a CryptoKey created non-extractable', async () => {
    const { privateKey } = await generateKeyPair('EdDSA', { extractable: false });
    await expect(new CompactJwsAuditSigner(ref(), privateKey).verifier()).resolves.toBeUndefined();
  });

  it('is derived once', async () => {
    const signer = await jwkSigner();
    expect(await signer.verifier()).toBe(await signer.verifier());
  });
});

describe('publicJwkOf', () => {
  it('keeps only the public members of an Ed25519 or P-256 private key', async () => {
    const okp = await exportJWK((await generateKeyPair('EdDSA', { extractable: true })).privateKey);
    expect(await publicJwkOf({ ...okp, kid: 'k', alg: 'EdDSA', use: 'sig' }))
      .toEqual({ kty: 'OKP', crv: okp.crv, x: okp.x });
    const ec = await exportJWK((await generateKeyPair('ES256', { extractable: true })).privateKey);
    expect(await publicJwkOf(ec)).toEqual({ kty: 'EC', crv: 'P-256', x: ec.x, y: ec.y });
  });

  it('yields nothing from a public key, a secret key or a key type no audit algorithm uses', async () => {
    const { publicKey } = await generateKeyPair('EdDSA', { extractable: true });
    const okp = await exportJWK(publicKey);
    const rsa = await exportJWK((await generateKeyPair('RS256', { extractable: true })).privateKey);
    for (const key of [
      publicKey,
      okp,
      generateKeyPairSync('ed25519').publicKey,
      rsa,
      { kty: 'oct', k: 'c2VjcmV0' },
      { kty: 'OKP', crv: 'Ed25519', d: 'AAAA' },
    ]) {
      await expect(publicJwkOf(key as JWK)).resolves.toBeUndefined();
    }
  });
});

describe('a recorder and a builder whose signing key yields its public key, given no verifier', () => {
  it('refuse to build on an entry their key did not sign', async () => {
    for (const [form, key] of Object.entries(await privateKeyForms())) {
      const signer = new CompactJwsAuditSigner(ref(), key);
      const journal = await journalWithForgery(signer);
      await expect(record(recorderWith(journal, signer), 'evt_2', 2), form).rejects.toMatchObject({
        code: AUDIT_ERROR_CODES.JOURNAL_FAILURE,
        message: 'Audit journal entry is not one its recorder signed',
        details: { sequence: '2' },
      });
      await expect(builderWith(journal, signer).createCheckpoint(ledger), form).rejects.toMatchObject({
        code: AUDIT_ERROR_CODES.JOURNAL_FAILURE,
        message: 'Audit journal entry is not one its recorder signed',
        details: { sequence: '2' },
      });
    }
  });

  it('build on what another process recorded with the same key', async () => {
    const signer = await jwkSigner();
    const journal = new MemoryAuditJournal();
    await record(recorderWith(journal, signer), 'evt_1', 1);
    await expect(record(recorderWith(journal, signer), 'evt_2', 2))
      .resolves.toMatchObject({ core: { sequence: '2' } });
    await expect(builderWith(journal, signer).createCheckpoint(ledger))
      .resolves.toMatchObject({ core: { treeSize: '3' } });
  });

  it('refuse, for a recorder, a head recorded under another key, whatever verifier it is given', async () => {
    const signer = await jwkSigner();
    const journal = new MemoryAuditJournal();
    await record(recorderWith(journal, signer), 'evt_1', 1);
    const other = await jwkSigner('key-2');
    const head = (await journal.getHead(ledger))!;
    const entry = await unsignedEntryAfter(head, { recorder: other.ref, signWith: other });
    await insert(journal, entry, '9');
    const acceptsAny: AuditSignatureVerifier = { verify: async () => true };
    for (const verifier of [undefined, acceptsAny]) {
      await expect(record(recorderWith(journal, signer, verifier), 'evt_2', 2)).rejects.toMatchObject({
        code: AUDIT_ERROR_CODES.JOURNAL_FAILURE,
        message: 'Audit journal entry is not one its recorder signed',
        details: { sequence: '2' },
      });
    }
  });

  it('use the verifier passed, and never derive one, when one is passed', async () => {
    const signer = await jwkSigner();
    const journal = new MemoryAuditJournal();
    await record(recorderWith(journal, signer), 'evt_1', 1);
    const derive = vi.spyOn(signer, 'verifier');
    const given = (await new CompactJwsAuditSigner(signer.ref, await exportJWK(
      (await generateKeyPair('EdDSA', { extractable: true })).privateKey,
    )).verifier())!;
    await expect(record(recorderWith(journal, signer, given), 'evt_2', 2))
      .rejects.toMatchObject({ message: 'Audit journal entry is not one its recorder signed' });
    await expect(builderWith(journal, signer, given).createCheckpoint(ledger))
      .rejects.toMatchObject({ message: 'Audit journal entry is not one its recorder signed' });
    expect(derive).not.toHaveBeenCalled();
  });

  it('refuse, and derive again next time, when the signer fails to derive its verifier', async () => {
    const real = await jwkSigner();
    const journal = new MemoryAuditJournal();
    await record(recorderWith(journal, real), 'evt_1', 1);
    const failure = new Error('key store unavailable');
    const flaky: AuditSigner = {
      ref: real.ref,
      sign: (bytes) => real.sign(bytes),
      verifier: vi.fn<() => Promise<AuditSignatureVerifier | undefined>>()
        .mockRejectedValueOnce(failure)
        .mockRejectedValueOnce(failure)
        .mockImplementation(() => real.verifier()),
    };
    const recorder = recorderWith(journal, flaky);
    const builder = builderWith(journal, flaky);
    const refused = {
      code: AUDIT_ERROR_CODES.INVALID_CONFIGURATION,
      message: 'The audit signer could not derive a verifier of its own signatures',
      cause: failure,
    };
    await expect(record(recorder, 'evt_2', 2)).rejects.toMatchObject(refused);
    await expect(builder.createCheckpoint(ledger)).rejects.toMatchObject(refused);
    await expect(record(recorder, 'evt_2', 2)).resolves.toMatchObject({ core: { sequence: '2' } });
    await expect(builder.createCheckpoint(ledger)).resolves.toMatchObject({ core: { treeSize: '3' } });
  });
});

describe('a recorder and a builder whose signing key does not yield its public key, given no verifier', () => {
  it('trust the journal as written, as before', async () => {
    const { privateKey } = await generateKeyPair('EdDSA', { extractable: false });
    const signer = new CompactJwsAuditSigner(ref(), privateKey);
    const journal = await journalWithForgery(signer);
    await expect(record(recorderWith(journal, signer), 'evt_2', 2))
      .resolves.toMatchObject({ core: { sequence: '3' } });
    await expect(builderWith(journal, signer).createCheckpoint(ledger))
      .resolves.toMatchObject({ core: { treeSize: '4' } });
  });
});

describe('CompactJwsAuditSignatureVerifier over a derived key', () => {
  it('is what the signer derives', async () => {
    const signer = await jwkSigner();
    expect(await signer.verifier()).toBeInstanceOf(CompactJwsAuditSignatureVerifier);
  });
});
