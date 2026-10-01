import { afterEach, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { NodeCryptoProvider, generateDidKeyFromBase64 } from '@kya-os/mcp';
import { CommerceJournal } from '../src/commerce/journal.js';
import { PaymentCoordinator } from '../src/commerce/payments.js';
import { X402Rail } from '../src/payments/x402.js';

const directories: string[] = [];
const children: ChildProcessWithoutNullStreams[] = [];
afterEach(async () => {
  await Promise.all(children.splice(0).map(child => {
    if (child.exitCode !== null || child.signalCode !== null) return;
    return new Promise<void>(resolve => { child.once('close', () => resolve()); child.kill('SIGKILL'); });
  }));
  directories.splice(0).forEach(directory => fs.rmSync(directory, { recursive: true, force: true }));
});
const moduleUrl = (name: string) => JSON.stringify(new URL(`../src/${name}.ts`, import.meta.url).href);

it('atomically reserves a UCP idempotency key across processes before either distinct checkout can settle', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'ucp-process-idempotency-')); directories.push(directory);
  const file = path.join(directory, 'commerce.json');
  const keys = await new NodeCryptoProvider().generateKeyPair();
  const did = generateDidKeyFromBase64(keys.publicKey);
  const owner = { did, kid: `${did}#${did.slice(8)}`, privateKeyBase64: keys.privateKey, publicKeyBase64: keys.publicKey };
  const journal = new CommerceJournal(file);
  const coordinator = new PaymentCoordinator({ journal, rail: new X402Rail({ mode: 'sandbox' }), origin: 'https://merchant.example', authorize: async () => { throw new Error('Preparation must not authorize'); } });
  const checkouts = await Promise.all(['one', 'two'].map(async id => {
    const record = await coordinator.prepare({ id, owner: did, product: 'risotto', quantity: 2, protocol: 'ucp', rail: 'sandbox-token' });
    await coordinator.confirm(id, record.reviewToken, record.termsDigest);
    return { record, token: await coordinator.tokenize(id, did) };
  }));
  const fixture = path.join(directory, 'fixture.json');
  fs.writeFileSync(fixture, JSON.stringify({ file, owner, checkouts }), { mode: 0o600 });
  const source = `
    import fs from 'node:fs';
    import { CommerceJournal } from ${moduleUrl('commerce/journal')};
    import { PaymentCoordinator } from ${moduleUrl('commerce/payments')};
    import { createUcpBackend } from ${moduleUrl('commerce/backend')};
    import { X402Rail } from ${moduleUrl('payments/x402')};
    import { signMessage } from ${moduleUrl('lib/consent-protocol')};
    import { ucpPlatformProfile } from ${moduleUrl('commerce/ucp')};
    const { file, owner, checkouts } = JSON.parse(fs.readFileSync(process.argv[1], 'utf8'));
    const { record, token } = checkouts[Number(process.argv[2])];
    const journal = new CommerceJournal(file);
    const merchantDid = 'did:key:merchant-fixture', origin = 'https://merchant.example';
    const coordinator = new PaymentCoordinator({ journal, rail: new X402Rail({ mode: 'sandbox' }), origin,
      authorize: async (_args, execution) => {
        const response = await execution({ vc: { credentialSubject: { id: owner.did } },
          outcome: { ok: true, quantity: 2, total: 'CHF 39.80', currency: 'CHF', item: { uri: record.productUri, unitPrice: '19.90' } }, evidence: {} });
        return { content: [{ type: 'text', text: JSON.stringify(response.body) }] };
      },
      onPayment: async event => { if (event.phase === 'completed') fs.appendFileSync(file + '.effects', event.checkoutId + '\\n'); },
    });
    const backend = createUcpBackend({ coordinator, merchantDid, origin });
    const profile = origin + '/agent/.well-known/ucp';
    const idempotencyKey = 'same-operation';
    const body = { payment: { instruments: [{ id: 'pi-demo', handler_id: 'kya_sandbox_token', type: 'sandbox-token', credential: { type: 'sandbox-token', token } }] } };
    const clean = { product: record.product, quantity: record.quantity, checkout: { id: record.id, protocol: 'ucp', termsDigest: record.termsDigest } };
    const args = { ...clean, _kyaos_proof: (await signMessage('place_order', clean, owner, merchantDid)).proof };
    const proof = await signMessage('ucp.complete', { id: record.id, body, idempotencyKey, profile }, owner, merchantDid);
    const exclusive = journal.exclusive.bind(journal);
    let firstReservation = true;
    journal.exclusive = async operation => {
      // Pause immediately before the first journal lock. Both real processes
      // have already observed the request key as absent at this point.
      if (firstReservation) {
        firstReservation = false;
        process.stdout.write('RESERVATION_READY\\n');
        await new Promise(resolve => process.stdin.once('data', resolve));
      }
      return exclusive(operation);
    };
    const result = await backend.execute({ operation: 'complete', id: record.id, body, rawBody: JSON.stringify(body), requestId: record.id, idempotencyKey,
      headers: { 'x-kya-request': Buffer.from(JSON.stringify(proof)).toString('base64'), 'x-kya-order': Buffer.from(JSON.stringify({ args })).toString('base64') },
      platform: { url: profile, profile: ucpPlatformProfile(origin), handlers: ['sandbox-token'] },
    });
    process.stdout.write(JSON.stringify('checkout' in result ? { state: result.checkout.status } : { status: result.status, error: result.error.code }) + '\\n');
    process.stdin.destroy();
  `;
  const workers = [0, 1].map(index => {
    const child = spawn(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', source, fixture, String(index)], {
      cwd: fileURLToPath(new URL('..', import.meta.url)), stdio: ['pipe', 'pipe', 'pipe'],
    });
    children.push(child);
    let output = '', error = '';
    child.stdout.on('data', data => { output += String(data); });
    child.stderr.on('data', data => { error += String(data); });
    const done = new Promise<{ code: number | null; output: string; error: string }>((resolve, reject) => {
      child.once('error', reject); child.once('close', code => resolve({ code, output, error }));
    });
    return { child, done, ready: () => output.includes('RESERVATION_READY') };
  });
  await Promise.all(workers.map(worker => expect.poll(worker.ready, { timeout: 8_000, interval: 20 }).toBe(true)));
  workers.forEach(worker => worker.child.stdin.write('GO'));
  const results = await Promise.all(workers.map(worker => worker.done));
  expect(results.every(result => result.code === 0), JSON.stringify(results)).toBe(true);
  const outcomes = results.map(result => JSON.parse(result.output.trim().split('\n').at(-1)!));
  expect(outcomes).toContainEqual({ state: 'completed' });
  expect(outcomes).toContainEqual({ status: 409, error: 'IDEMPOTENCY_CONFLICT' });
  expect(Object.values(journal.read().records).filter(record => record.state === 'settled')).toHaveLength(1);
  expect(fs.readFileSync(`${file}.effects`, 'utf8').trim().split('\n')).toHaveLength(1);
}, 12_000);
