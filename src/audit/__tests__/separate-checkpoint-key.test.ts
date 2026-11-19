import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from 'vitest';
import { logger } from '../../logging/index.js';
import type { AuditSignatureVerifier } from '../crypto.js';
import { AUDIT_ERROR_CODES } from '../errors.js';
import { MemoryAuditJournal } from '../providers/memory-journal.js';
import type { SignerRef } from '../types.js';
import { MAX_WARNED_RECORDER_KEYS } from '../unverified-recorder-keys.js';
import { ledger } from './observer-fixtures.js';
import {
  builderWith,
  insert,
  jwkSigner,
  record,
  recorderWith,
  unsignedEntryAfter,
} from './stored-entry-fixtures.js';

const WARNED = Symbol.for('@kya-os/mcp/audit-unverified-recorder-keys');
const MORE_WARNED = Symbol.for('@kya-os/mcp/audit-unverified-recorder-keys-more');
const registry = globalThis as { [key: symbol]: unknown };

let warn: MockInstance<typeof logger.warn>;

beforeEach(() => {
  delete registry[WARNED];
  delete registry[MORE_WARNED];
  warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
});

afterEach(() => {
  delete registry[WARNED];
  delete registry[MORE_WARNED];
  vi.restoreAllMocks();
});

const forgedMessage = 'Audit journal entry is not one its recorder signed';

describe('a checkpoint builder that signs with another key than the recorder', () => {
  it('builds checkpoints over honest entries with no signatures, and warns once for the recorder key', async () => {
    const recorderKey = await jwkSigner('recorder');
    const checkpointKey = await jwkSigner('checkpoints');
    const journal = new MemoryAuditJournal();
    const recorder = recorderWith(journal, recorderKey);
    await record(recorder, 'evt_1', 1);
    const builder = builderWith(journal, checkpointKey);
    await expect(builder.createCheckpoint(ledger))
      .resolves.toMatchObject({ core: { treeSize: '2', issuer: checkpointKey.ref } });
    await record(recorder, 'evt_2', 2);
    await expect(builder.createCheckpoint(ledger)).resolves.toMatchObject({ core: { treeSize: '3' } });
    await expect(builderWith(journal, checkpointKey).createCheckpoint(ledger))
      .resolves.toMatchObject({ core: { treeSize: '3' } });

    expect(warn).toHaveBeenCalledTimes(1);
    const [message] = warn.mock.calls[0]!;
    expect(message).toContain(JSON.stringify(recorderKey.ref.kid));
    expect(message).toContain('Pass signatures that resolve that key to verify them');
  });

  it('refuses, with no signatures, a leaf under another key than the genesis names', async () => {
    const recorderKey = await jwkSigner('recorder');
    const journal = new MemoryAuditJournal();
    await record(recorderWith(journal, recorderKey), 'evt_1', 1);
    const claimed: SignerRef = { did: 'did:key:zElsewhere', kid: 'did:key:zElsewhere#k', alg: 'EdDSA' };
    await insert(journal, await unsignedEntryAfter((await journal.getHead(ledger))!, { recorder: claimed }), '9');

    await expect(builderWith(journal, await jwkSigner('checkpoints')).createCheckpoint(ledger)).rejects.toMatchObject({
      code: AUDIT_ERROR_CODES.JOURNAL_FAILURE, message: forgedMessage, details: { sequence: '2' },
    });
    expect(warn.mock.calls.map(([message]) => message).join('\n')).not.toContain('zElsewhere');
  });

  it('refuses a forged entry, and any entry under a key it cannot resolve, when given signatures', async () => {
    const recorderKey = await jwkSigner('recorder');
    const checkpointKey = await jwkSigner('checkpoints');
    const signatures = (await recorderKey.verifier())!;
    const unknownKey = await jwkSigner('unknown');
    const variants: Array<[string, { recorder: SignerRef; signWith?: typeof unknownKey }]> = [
      ['a receipt the recorder key never signed', { recorder: recorderKey.ref }],
      ['a receipt signed by a key the verifier does not resolve', { recorder: unknownKey.ref, signWith: unknownKey }],
    ];
    for (const [name, options] of variants) {
      const journal = new MemoryAuditJournal();
      await record(recorderWith(journal, recorderKey), 'evt_1', 1);
      await insert(journal, await unsignedEntryAfter((await journal.getHead(ledger))!, options), '9');
      await expect(builderWith(journal, checkpointKey, signatures).createCheckpoint(ledger), name)
        .rejects.toMatchObject({
          code: AUDIT_ERROR_CODES.JOURNAL_FAILURE, message: forgedMessage, details: { sequence: '2' },
        });
    }
    expect(warn).not.toHaveBeenCalled();
  });

  it('still refuses, with no signatures, a leaf that does not chain to the one before it', async () => {
    const recorderKey = await jwkSigner('recorder');
    const journal = new MemoryAuditJournal();
    await record(recorderWith(journal, recorderKey), 'evt_1', 1);
    await insert(journal, await unsignedEntryAfter((await journal.getHead(ledger))!, {
      recorder: recorderKey.ref, previousEntryDigest: `sha256:${'7'.repeat(64)}`,
    }), '9');
    await expect(builderWith(journal, await jwkSigner('checkpoints')).createCheckpoint(ledger))
      .rejects.toMatchObject({ code: AUDIT_ERROR_CODES.JOURNAL_FAILURE, details: { sequence: '2' } });
  });
});

describe('a checkpoint builder that signs with the recorder key, given no signatures', () => {
  it('refuses a forged entry under that key, and warns of nothing', async () => {
    const signer = await jwkSigner();
    const journal = new MemoryAuditJournal();
    await record(recorderWith(journal, signer), 'evt_1', 1);
    await insert(journal, await unsignedEntryAfter((await journal.getHead(ledger))!, { recorder: signer.ref }), '9');
    await expect(builderWith(journal, signer).createCheckpoint(ledger)).rejects.toMatchObject({
      code: AUDIT_ERROR_CODES.JOURNAL_FAILURE, message: forgedMessage, details: { sequence: '2' },
    });
    expect(warn).not.toHaveBeenCalled();
  });

  it('refuses an entry under another key than the genesis names, with or without signatures, and warns of nothing', async () => {
    const signer = await jwkSigner();
    const journal = new MemoryAuditJournal();
    await record(recorderWith(journal, signer), 'evt_1', 1);
    const claimed: SignerRef = { did: 'did:key:zElsewhere', kid: 'did:key:zElsewhere#k', alg: 'EdDSA' };
    await insert(journal, await unsignedEntryAfter((await journal.getHead(ledger))!, { recorder: claimed }), '9');

    await expect(builderWith(journal, signer).createCheckpoint(ledger)).rejects.toMatchObject({
      code: AUDIT_ERROR_CODES.JOURNAL_FAILURE, message: forgedMessage, details: { sequence: '2' },
    });
    const signatures: AuditSignatureVerifier = (await signer.verifier())!;
    await expect(builderWith(journal, signer, signatures).createCheckpoint(ledger))
      .rejects.toMatchObject({ message: forgedMessage, details: { sequence: '2' } });
    expect(warn).not.toHaveBeenCalled();
  });
});

describe('the recorder key a checkpoint builder warns of', () => {
  it('is the one the genesis names, quoted as JSON with what does not print replaced', async () => {
    const recorderKey = await jwkSigner('k\u001b[2J\u202e');
    const journal = new MemoryAuditJournal();
    await record(recorderWith(journal, recorderKey), 'evt_1', 1);

    await expect(builderWith(journal, await jwkSigner('checkpoints')).createCheckpoint(ledger))
      .resolves.toMatchObject({ core: { treeSize: '2' } });
    expect(warn).toHaveBeenCalledTimes(1);
    const [message] = warn.mock.calls[0]!;
    // Quoted as JSON, which escapes a control character, with a format character replaced.
    expect(message).toContain('"did:key:zRecorder#k\\u001b[2J\ufffd"');
    expect(message).not.toMatch(/[\u001b\u202e]/);
  });

  it('names at most a bounded number of keys in a process, then says once that there are more', async () => {
    const checkpointKey = await jwkSigner('checkpoints');
    const keys = MAX_WARNED_RECORDER_KEYS + 3;
    for (let n = 0; n < keys; n += 1) {
      const journal = new MemoryAuditJournal();
      await record(recorderWith(journal, await jwkSigner(`k${n}`)), 'evt_1', 1);
      await expect(builderWith(journal, checkpointKey).createCheckpoint(ledger))
        .resolves.toMatchObject({ core: { treeSize: '2' } });
    }
    expect(warn).toHaveBeenCalledTimes(MAX_WARNED_RECORDER_KEYS + 1);
    expect(warn.mock.calls.at(-1)![0]).toMatch(/more keys than this process names/);
    expect(warn.mock.calls.slice(0, -1).map(([message]) => message).join('\n'))
      .not.toContain(`#k${MAX_WARNED_RECORDER_KEYS}"`);
  });
});
