import { base64urlDecodeToBytes, base64urlEncodeFromBytes } from '../utils/base64.js';
import type { AuditHasher } from './crypto.js';
import { AUDIT_ERROR_CODES, AuditProtocolError } from './errors.js';
import type {
  AuditEvidenceProvider,
  EncryptedEvidenceInput,
  EvidenceAccessContext,
  EvidenceRetentionCommand,
  EvidenceRetentionResult,
} from './providers/evidence.js';
import type { Digest, EvidenceRef } from './types.js';

export interface EvidenceEncryptionInput {
  plaintext: Uint8Array;
  mediaType: string;
  key: CryptoKey;
  keyId: string;
  aad: Uint8Array;
  plaintextCommitment?: Digest;
}

export interface EvidenceEncryptorConfig {
  crypto: Crypto;
  hasher: AuditHasher;
  randomBytes(length: number): Promise<Uint8Array>;
}

/** Randomized AES-256-GCM evidence encryption with opaque object addressing. */
export class WebCryptoEvidenceEncryptor {
  constructor(private readonly config: EvidenceEncryptorConfig) {}

  async encrypt(input: EvidenceEncryptionInput): Promise<EncryptedEvidenceInput> {
    if (input.key.algorithm.name !== 'AES-GCM') {
      throw new TypeError('Evidence encryption key must use AES-GCM');
    }
    if (input.aad.byteLength === 0) {
      throw new TypeError('Evidence encryption requires entity-scoped authenticated data');
    }
    const nonce = await this.config.randomBytes(12);
    const objectRandom = await this.config.randomBytes(16);
    const encrypted = await this.config.crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: toArrayBuffer(nonce),
        additionalData: toArrayBuffer(input.aad),
        tagLength: 128,
      },
      input.key,
      toArrayBuffer(input.plaintext),
    );
    const ciphertext = new Uint8Array(encrypted);
    const ciphertextDigest = await this.config.hasher.sha256(ciphertext);
    const aadDigest = await this.config.hasher.sha256(input.aad);
    const ref: EvidenceRef = {
      objectId: `evi_${base64urlEncodeFromBytes(objectRandom)}`,
      ciphertextDigest,
      ...(input.plaintextCommitment
        ? { plaintextCommitment: input.plaintextCommitment }
        : {}),
      mediaType: input.mediaType,
      size: String(ciphertext.byteLength),
      encryption: {
        suite: 'A256GCM',
        keyId: input.keyId,
        nonce: base64urlEncodeFromBytes(nonce),
        aadDigest,
      },
    };
    return { ref: Object.freeze(ref), ciphertext };
  }

  async decrypt(
    input: EncryptedEvidenceInput,
    key: CryptoKey,
    aad: Uint8Array,
  ): Promise<Uint8Array> {
    if (aad.byteLength === 0) {
      throw new TypeError('Evidence decryption requires entity-scoped authenticated data');
    }
    const ciphertextDigest = await this.config.hasher.sha256(input.ciphertext);
    const aadDigest = await this.config.hasher.sha256(aad);
    if (ciphertextDigest !== input.ref.ciphertextDigest ||
      aadDigest !== input.ref.encryption.aadDigest) {
      throw new AuditProtocolError(
        AUDIT_ERROR_CODES.EVIDENCE_INTEGRITY,
        'Evidence ciphertext or authenticated metadata digest does not match',
      );
    }
    try {
      const plaintext = await this.config.crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: toArrayBuffer(base64urlDecodeToBytes(input.ref.encryption.nonce)),
          additionalData: toArrayBuffer(aad),
          tagLength: 128,
        },
        key,
        toArrayBuffer(input.ciphertext),
      );
      return new Uint8Array(plaintext);
    } catch (error) {
      throw new AuditProtocolError(
        AUDIT_ERROR_CODES.EVIDENCE_INTEGRITY,
        'Evidence AEAD verification failed',
        undefined,
        { cause: error },
      );
    }
  }
}

interface EvidenceState {
  ref: EvidenceRef;
  ciphertext: Uint8Array | null;
  holds: Set<string>;
}

export interface MemoryAuditEvidenceProviderOptions {
  authorizeAccess?(input: {
    ref: EvidenceRef;
    context: EvidenceAccessContext;
  }): Promise<boolean> | boolean;
  onAccess?(input: {
    ref: EvidenceRef;
    context: EvidenceAccessContext;
    result: 'found' | 'missing' | 'disposed' | 'denied';
  }): Promise<void> | void;
}

export class MemoryAuditEvidenceProvider implements AuditEvidenceProvider {
  private readonly states = new Map<string, EvidenceState>();

  constructor(
    private readonly hasher: AuditHasher,
    private readonly options: MemoryAuditEvidenceProviderOptions = {},
  ) {}

  async putIfAbsent(input: EncryptedEvidenceInput): Promise<EvidenceRef> {
    const actualDigest = await this.hasher.sha256(input.ciphertext);
    if (actualDigest !== input.ref.ciphertextDigest ||
      String(input.ciphertext.byteLength) !== input.ref.size) {
      throw new AuditProtocolError(
        AUDIT_ERROR_CODES.EVIDENCE_INTEGRITY,
        'Evidence bytes do not match their ciphertext digest or size',
      );
    }
    const existing = this.states.get(input.ref.objectId);
    if (existing !== undefined) {
      if (existing.ref.ciphertextDigest !== input.ref.ciphertextDigest ||
        existing.ciphertext === null ||
        !bytesEqual(existing.ciphertext, input.ciphertext)) {
        throw new AuditProtocolError(
          AUDIT_ERROR_CODES.EVIDENCE_INTEGRITY,
          'Opaque evidence object ID collision',
        );
      }
      return existing.ref;
    }
    this.states.set(input.ref.objectId, {
      ref: input.ref,
      ciphertext: new Uint8Array(input.ciphertext),
      holds: new Set<string>(),
    });
    return input.ref;
  }

  async has(ref: EvidenceRef): Promise<boolean> {
    return this.states.get(ref.objectId)?.ciphertext !== null &&
      this.states.has(ref.objectId);
  }

  async get(ref: EvidenceRef, context: EvidenceAccessContext): Promise<Uint8Array | null> {
    if (this.options.authorizeAccess !== undefined &&
      !(await this.options.authorizeAccess({ ref, context }))) {
      await this.options.onAccess?.({ ref, context, result: 'denied' });
      throw new AuditProtocolError(
        AUDIT_ERROR_CODES.EVIDENCE_ACCESS_DENIED,
        'Evidence access policy denied this actor and purpose',
      );
    }
    const state = this.states.get(ref.objectId);
    const result = state === undefined
      ? 'missing'
      : state.ciphertext === null ? 'disposed' : 'found';
    await this.options.onAccess?.({ ref, context, result });
    return state?.ciphertext === null || state === undefined
      ? null
      : new Uint8Array(state.ciphertext);
  }

  async applyRetention(command: EvidenceRetentionCommand): Promise<EvidenceRetentionResult> {
    const state = this.states.get(command.ref.objectId);
    if (state === undefined) return { ref: command.ref, state: 'missing' };

    if (command.kind === 'legal_hold') {
      state.holds.add(command.holdId);
      return { ref: state.ref, state: 'held' };
    }
    if (command.kind === 'release_hold') {
      state.holds.delete(command.holdId);
      return {
        ref: state.ref,
        state: state.ciphertext === null ? 'disposed' : state.holds.size > 0 ? 'held' : 'retained',
      };
    }
    if (state.holds.size > 0) {
      throw new AuditProtocolError(
        AUDIT_ERROR_CODES.EVIDENCE_LEGAL_HOLD,
        'Evidence cannot be disposed while a legal hold is active',
        { holdIds: [...state.holds] },
      );
    }
    state.ciphertext = null;
    return { ref: state.ref, state: 'disposed' };
  }
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return Uint8Array.from(bytes).buffer;
}
