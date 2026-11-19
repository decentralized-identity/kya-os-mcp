import { exportJWK, generateKeyPair } from 'jose';
import { describe, expect, it, vi } from 'vitest';
import { NodeCryptoProvider } from '../../providers/node-crypto.js';
import { runAuditCli, type AuditCliIo } from '../cli.js';
import { CompactJwsAuditSigner, CryptoProviderAuditHasher, hashAuditValue } from '../crypto.js';
import { MemoryAuditJournal } from '../providers/memory-journal.js';
import { AuditRecorderService } from '../recorder-service.js';
import { AUDIT_BUNDLE_MEDIA_TYPES, AuditReplayBundleExporter } from '../replay-bundle.js';
import type { AuditVerificationPolicyV1 } from '../types.js';
import { producerEvent, tenantRef } from './audit-fixtures.js';

const ledger = { ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_1' };
const SIGNED_AT = 1_750_000_001_000;
const DAY = 86_400_000;

type Report = Record<string, { verdict: string; reasonCodes: string[] }>;

/**
 * A bundle of one recorded call, signed at `SIGNED_AT` by one key that records and exports, with
 * the policy that names that key valid until `validUntil` under `keyRevocationMode`.
 */
async function signedBundle(validUntil: number, keyRevocationMode: AuditVerificationPolicyV1['keyRevocationMode']) {
  const hasher = new CryptoProviderAuditHasher(new NodeCryptoProvider());
  const { publicKey, privateKey } = await generateKeyPair('EdDSA', { extractable: true });
  const ref = { did: 'did:web:audit.example', kid: 'did:web:audit.example#recorder', alg: 'EdDSA' as const };
  const signer = new CompactJwsAuditSigner(ref, privateKey);
  const journal = new MemoryAuditJournal();
  await new AuditRecorderService({
    ...ledger, tenantRef, binding: 'urn:kya-os:audit-binding:mcp:2025-11-25', sourceId: 'recorder',
    journal, signer, hasher, clock: { now: () => SIGNED_AT },
  }).submitAuthenticated(
    { ledgerId: ledger.ledgerId, producerEvent: producerEvent('evt_1', 1), encryptedEvidence: [] },
    { producerAuthority: 'did:key:zProducer', tenantAuthority: 'tenant-1', tenantRef },
  );
  const entries = await journal.snapshot(ledger);
  const policy: AuditVerificationPolicyV1 = {
    policyId: 'policy:cli',
    trustedLedgerEpochs: [{ ...ledger, recorderKeys: [{ signer: ref, validUntil }] }],
    trustedObservers: [],
    authorizedExporters: [{
      signerKeys: [{ signer: ref, validUntil }],
      allowedLedgerIds: [ledger.ledgerId],
      allowedPurposes: ['regulatory-review'],
    }],
    acceptedIntegritySuites: ['KYA-AUDIT-JCS-SHA256-JWS-2026', 'KYA-AUDIT-BUNDLE-JCS-SHA256-JWS-2026'],
    acceptedAlgorithms: ['EdDSA'],
    keyRevocationMode,
  };
  const bundle = await new AuditReplayBundleExporter({ hasher, signer, clock: { now: () => SIGNED_AT + 1_000 } })
    .export({
      bundleId: 'bundle', purpose: 'regulatory-review',
      verificationPolicyDigest: await hashAuditValue(hasher, 'org.kya-os.audit.verification-policy.v1', policy),
      selections: [{
        ...ledger, firstSequence: '0', lastSequence: String(entries.length - 1),
        expectedHeadDigest: entries.at(-1)!.entryDigest, checkpointTreeSizes: [],
      }],
      components: [{
        path: 'entries.json', mediaType: AUDIT_BUNDLE_MEDIA_TYPES.entries, disposition: 'included', content: entries,
      }],
    });
  return {
    'bundle.json': JSON.stringify(bundle),
    'policy.json': JSON.stringify(policy),
    'keys.json': JSON.stringify({ keys: [{ kid: ref.kid, jwk: await exportJWK(publicKey) }] }),
  } as Record<string, string>;
}

async function verify(files: Record<string, string>) {
  const output: string[] = [];
  const errors: string[] = [];
  const io: AuditCliIo = {
    readText: async (path) => files[path]!,
    write: (text) => output.push(text),
    writeError: (text) => errors.push(text),
  };
  const exitCode = await runAuditCli(['verify', 'bundle.json', '--policy', 'policy.json', '--keys', 'keys.json'], io);
  return { exitCode, output: output.join(''), errors: errors.join('') };
}

describe('kya-audit verify: the policy constraints that need the present time', () => {
  it('exits 1 when the policy requires current keys and the signing key ended before now', async () => {
    const { exitCode, output } = await verify(await signedBundle(SIGNED_AT + DAY, 'current'));
    const report = JSON.parse(output) as Report;
    // Nothing in the bundle dates its records before the key ended.
    expect(report['cryptographicIntegrity']).toEqual({
      verdict: 'indeterminate', reasonCodes: ['AUDIT_KEY_ENDED_UNDATED'],
    });
    expect(report['currentAuthorization']).toMatchObject({ verdict: 'invalid' });
    expect(report['currentAuthorization']!.reasonCodes).toContain('AUDIT_KEY_NOT_CURRENT');
    expect(exitCode).toBe(1);
  });

  it('evaluates current keys under keyRevocationMode both as well', async () => {
    const { exitCode, output } = await verify(await signedBundle(SIGNED_AT + DAY, 'both'));
    expect((JSON.parse(output) as Report)['currentAuthorization']!.reasonCodes).toContain('AUDIT_KEY_NOT_CURRENT');
    expect(exitCode).toBe(1);
  });

  it('reads the clock once per run, so every check is made at one instant', async () => {
    const validUntil = SIGNED_AT + DAY;
    const files = await signedBundle(validUntil, 'current');
    // The key is valid at the first read of the clock and has ended at every later one.
    let reads = 0;
    const clock = vi.spyOn(Date, 'now').mockImplementation(() => (reads++ === 0 ? validUntil - 1 : validUntil + 1));
    try {
      const { exitCode, output } = await verify(files);
      expect((JSON.parse(output) as Report)['currentAuthorization']!.reasonCodes).not.toContain('AUDIT_KEY_NOT_CURRENT');
      expect(exitCode).toBe(0);
    } finally {
      clock.mockRestore();
    }
  });

  it('exits 0 when the signing key is still valid now', async () => {
    const { exitCode, output } = await verify(await signedBundle(Date.now() + DAY, 'current'));
    const report = JSON.parse(output) as Report;
    expect(report['currentAuthorization']!.reasonCodes).not.toContain('AUDIT_KEY_NOT_CURRENT');
    expect(report['currentAuthorization']!.reasonCodes).not.toContain('AUDIT_NOT_EVALUATED');
    expect(exitCode).toBe(0);
  });
});

describe('kya-audit verify: what reaches the terminal', () => {
  const ESC = '\u001b';
  const BEL = '\u0007';
  // eslint-disable-next-line no-control-regex
  const CONTROL = /[\u0000-\u0009\u000b-\u001f\u007f-\u009f]/;

  it('says a bundle that is not JSON is not JSON, and quotes none of it', async () => {
    const files = await signedBundle(Date.now() + DAY, 'as_observed');
    const { exitCode, errors, output } = await verify({
      ...files,
      'bundle.json': `{"manifest":${ESC}]0;verified${BEL}${ESC}[2J${ESC}[1;1HAudit verification passed`,
    });
    expect(exitCode).toBe(2);
    expect(output).toBe('');
    expect(errors).toBe('Audit verification failed: bundle.json is not valid JSON\n');
  });

  it('names the policy or key file that is not JSON, and quotes none of it', async () => {
    const files = await signedBundle(Date.now() + DAY, 'as_observed');
    for (const name of ['policy.json', 'keys.json']) {
      const { exitCode, errors } = await verify({ ...files, [name]: `{${ESC}[2J` });
      expect(exitCode).toBe(2);
      expect(errors).toBe(`Audit verification failed: ${name} is not valid JSON\n`);
    }
  });

  it('writes no control character from any message it prints', async () => {
    const files = await signedBundle(Date.now() + DAY, 'as_observed');
    const policy = JSON.parse(files['policy.json']!) as Record<string, unknown>;
    // A schema refusal of a member whose name holds an escape sequence.
    const { exitCode, errors } = await verify({
      ...files, 'policy.json': JSON.stringify({ ...policy, [`x${ESC}[2J`]: true }),
    });
    expect(exitCode).toBe(2);
    expect(errors).toMatch(/^Audit verification failed: /);
    expect(errors.slice(0, -1)).not.toMatch(CONTROL);
    expect(errors.endsWith('\n')).toBe(true);
  });

  it('names the file a schema refuses, and says why on one line', async () => {
    const files = await signedBundle(Date.now() + DAY, 'as_observed');
    const policy = await verify({ ...files, 'policy.json': '"not a policy"' });
    expect(policy.exitCode).toBe(2);
    expect(policy.errors).toMatch(/^Audit verification failed: policy\.json is not a valid verification policy: [^\n]*expected object[^\n]*\n$/);
    const keys = await verify({ ...files, 'keys.json': JSON.stringify({ keys: [{ kid: 'k', jwk: { kid: 'j' } }] }) });
    expect(keys.errors).toBe(
      'Audit verification failed: keys.json is not a valid key file: keys.0.jwk.kid: JWK kid must match the key-file kid\n',
    );
  });

  it('names a file it cannot read', async () => {
    const files = await signedBundle(Date.now() + DAY, 'as_observed');
    const { exitCode, errors } = await runAuditCliWith({
      ...files,
    }, 'keys.json');
    expect(exitCode).toBe(2);
    expect(errors).toMatch(/^Audit verification failed: keys\.json could not be read/);
    expect(errors.slice(0, -1)).not.toMatch(CONTROL);
    const thrownText = await runAuditCli(['verify', 'bundle.json', '--policy', 'policy.json', '--keys', 'keys.json'], {
      readText: async (path) => {
        if (path === 'bundle.json') throw 'device not ready'; // eslint-disable-line @typescript-eslint/only-throw-error
        return files[path]!;
      },
      write: () => undefined,
      writeError: (text) => expect(text).toBe('Audit verification failed: bundle.json could not be read: device not ready\n'),
    });
    expect(thrownText).toBe(2);
  });
});

/** Runs the CLI over `files`, with `unreadable` failing to read as a missing file does. */
async function runAuditCliWith(files: Record<string, string>, unreadable: string) {
  const errors: string[] = [];
  const exitCode = await runAuditCli(['verify', 'bundle.json', '--policy', 'policy.json', '--keys', 'keys.json'], {
    readText: async (path) => {
      if (path === unreadable) throw Object.assign(new Error(`ENOENT: no such file, open '${path}${'\u001b'}[2J'`), { code: 'ENOENT' });
      return files[path]!;
    },
    write: () => undefined,
    writeError: (text) => errors.push(text),
  });
  return { exitCode, errors: errors.join('') };
}
