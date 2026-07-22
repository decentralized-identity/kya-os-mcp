import { webcrypto } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import { CryptoProviderAuditHasher } from '../crypto.js';
import { AuditProtocolError } from '../errors.js';
import {
  MemoryAuditEvidenceProvider,
  WebCryptoEvidenceEncryptor,
} from '../evidence.js';

async function key(): Promise<CryptoKey> {
  return webcrypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
    'encrypt',
    'decrypt',
  ]);
}

function setup() {
  const crypto = new NodeCryptoProvider();
  const hasher = new CryptoProviderAuditHasher(crypto);
  const encryptor = new WebCryptoEvidenceEncryptor({
    crypto: webcrypto as unknown as Crypto,
    hasher,
    randomBytes: (length) => crypto.randomBytes(length),
  });
  const provider = new MemoryAuditEvidenceProvider(hasher);
  return { encryptor, provider };
}

const entityAad = new TextEncoder().encode('tenant-1:evidence');

describe('encrypted audit evidence', () => {
  it('uses randomized AEAD and opaque addressing instead of convergent encryption', async () => {
    const { encryptor } = setup();
    const encryptionKey = await key();
    const plaintext = new TextEncoder().encode('same sensitive proof');
    const input = {
      plaintext,
      mediaType: 'application/json',
      key: encryptionKey,
      keyId: 'tenant-key-v1',
      aad: entityAad,
    } as const;

    const first = await encryptor.encrypt(input);
    const second = await encryptor.encrypt(input);

    expect(first.ref.objectId).not.toBe(second.ref.objectId);
    expect(first.ref.encryption.nonce).not.toBe(second.ref.encryption.nonce);
    expect(first.ref.ciphertextDigest).not.toBe(second.ref.ciphertextDigest);
    expect(first.ref.plaintextCommitment).toBeUndefined();
    expect(await encryptor.decrypt(first, encryptionKey, input.aad)).toEqual(plaintext);
  });

  it('persists exact ciphertext idempotently and rejects object-ID collisions', async () => {
    const { encryptor, provider } = setup();
    const encrypted = await encryptor.encrypt({
      plaintext: new TextEncoder().encode('proof'),
      mediaType: 'application/json',
      key: await key(),
      keyId: 'tenant-key-v1',
      aad: entityAad,
    });

    await expect(provider.putIfAbsent(encrypted)).resolves.toEqual(encrypted.ref);
    await expect(provider.putIfAbsent(encrypted)).resolves.toEqual(encrypted.ref);
    await expect(provider.putIfAbsent({
      ref: encrypted.ref,
      ciphertext: new Uint8Array([1, 2, 3]),
    })).rejects.toMatchObject<Partial<AuditProtocolError>>({
      code: 'AUDIT_EVIDENCE_INTEGRITY',
    });
  });

  it('enforces legal hold before disposal and returns copies on read', async () => {
    const { encryptor, provider } = setup();
    const encrypted = await encryptor.encrypt({
      plaintext: new TextEncoder().encode('held proof'),
      mediaType: 'application/json',
      key: await key(),
      keyId: 'tenant-key-v1',
      aad: entityAad,
    });
    await provider.putIfAbsent(encrypted);
    await provider.applyRetention({
      kind: 'legal_hold',
      ref: encrypted.ref,
      holdId: 'case-1',
      authorizedBy: 'auditor',
    });

    await expect(provider.applyRetention({
      kind: 'dispose',
      ref: encrypted.ref,
      authorizedBy: 'retention-service',
      reason: 'ttl elapsed',
    })).rejects.toMatchObject<Partial<AuditProtocolError>>({
      code: 'AUDIT_EVIDENCE_LEGAL_HOLD',
    });

    const read = await provider.get(encrypted.ref, { actor: 'auditor', purpose: 'case-1' });
    expect(read).toEqual(encrypted.ciphertext);
    read![0] = read![0]! ^ 0xff;
    expect(await provider.get(encrypted.ref, { actor: 'auditor', purpose: 'case-1' }))
      .toEqual(encrypted.ciphertext);

    await provider.applyRetention({
      kind: 'release_hold',
      ref: encrypted.ref,
      holdId: 'case-1',
      authorizedBy: 'auditor',
    });
    await expect(provider.applyRetention({
      kind: 'dispose',
      ref: encrypted.ref,
      authorizedBy: 'retention-service',
      reason: 'ttl elapsed',
    })).resolves.toMatchObject({ state: 'disposed' });
    expect(await provider.get(encrypted.ref, { actor: 'auditor', purpose: 'case-1' }))
      .toBeNull();
  });

  it('requires the configured evidence access policy before returning ciphertext', async () => {
    const { encryptor } = setup();
    const hasher = new CryptoProviderAuditHasher(new NodeCryptoProvider());
    const provider = new MemoryAuditEvidenceProvider(hasher, {
      authorizeAccess: async ({ context }) => context.purpose === 'regulatory-review',
    });
    const encrypted = await encryptor.encrypt({
      plaintext: new TextEncoder().encode('restricted'),
      mediaType: 'application/json', key: await key(), keyId: 'tenant-key-v1',
      aad: entityAad,
    });
    await provider.putIfAbsent(encrypted);
    await expect(provider.get(encrypted.ref, { actor: 'intruder', purpose: 'debug' }))
      .rejects.toMatchObject({ code: 'AUDIT_EVIDENCE_ACCESS_DENIED' });
    await expect(provider.get(encrypted.ref, {
      actor: 'auditor', purpose: 'regulatory-review',
    })).resolves.toEqual(encrypted.ciphertext);
  });

  it('rejects evidence encryption without entity-scoped authenticated data', async () => {
    const { encryptor } = setup();
    await expect(encryptor.encrypt({
      plaintext: new TextEncoder().encode('proof'),
      mediaType: 'application/json',
      key: await key(),
      keyId: 'tenant-key-v1',
      aad: new Uint8Array(),
    })).rejects.toThrow(/entity-scoped authenticated data/i);
  });
});
