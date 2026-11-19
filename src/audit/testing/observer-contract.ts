import type { AuditCheckpointObserverProvider } from '../providers/observer.js';
import type { SignedAuditCheckpointV1 } from '../types.js';
import {
  check,
  equalJson,
  expectContract,
  report,
  type AuditProviderContractCheck,
  type AuditProviderContractReport,
} from './contract-harness.js';

export interface AuditCheckpointProviderContractFixtures {
  first: SignedAuditCheckpointV1;
  next: SignedAuditCheckpointV1;
  conflict: SignedAuditCheckpointV1;
  rollback: SignedAuditCheckpointV1;
  /**
   * A larger checkpoint that does NOT directly link `first` but consistently
   * extends its tree; when provided, the observer must accept it as catch-up
   * after a missed publication.
   */
  gapped?: SignedAuditCheckpointV1;
  /**
   * A checkpoint of the ledger epoch of `first`, validly signed and larger
   * than it, over a history that does not extend its tree: what a holder of
   * the recorder key would sign after rewriting the observed history. The
   * observer must accept it on its own and refuse it once it has observed
   * `first`. Optional in the type so fixtures written before it still
   * compile; without it the contract fails, because no other fixture shows
   * that the observer checks an extension.
   */
  fork?: SignedAuditCheckpointV1;
}

/**
 * `checkpoint` with its signature changed and its core left as it is: the
 * first character of the last JWS segment is replaced, so the signature
 * bytes differ whatever the encoding leaves unused in its final character.
 */
function withBrokenSignature(checkpoint: SignedAuditCheckpointV1): SignedAuditCheckpointV1 {
  const jws = checkpoint.jws;
  const at = jws.lastIndexOf('.') + 1;
  const broken = at < jws.length
    ? `${jws.slice(0, at)}${jws[at] === 'A' ? 'B' : 'A'}${jws.slice(at + 1)}`
    : `${jws}A`;
  return { ...checkpoint, jws: broken };
}

async function refuses(
  provider: AuditCheckpointObserverProvider,
  checkpoint: SignedAuditCheckpointV1,
): Promise<boolean> {
  try {
    await provider.publish(checkpoint);
    return false;
  } catch {
    return true;
  }
}

async function expectLatest(
  provider: AuditCheckpointObserverProvider,
  checkpoint: SignedAuditCheckpointV1,
): Promise<void> {
  const latest = await provider.latest(checkpoint.core);
  expectContract(
    latest?.checkpoint.checkpointDigest === checkpoint.checkpointDigest &&
      latest.checkpoint.jws === checkpoint.jws,
    'a refused checkpoint replaced the latest observation',
  );
}

/** Executable monotonicity/split-view contract for independent observers. */
export async function evaluateAuditObserverProviderContract(input: {
  createProvider(): AuditCheckpointObserverProvider | Promise<AuditCheckpointObserverProvider>;
  fixtures: AuditCheckpointProviderContractFixtures;
}): Promise<AuditProviderContractReport> {
  const checks: AuditProviderContractCheck[] = [];
  await check(checks, 'retains monotonic linked observations and exact duplicates', async () => {
    const provider = await input.createProvider();
    expectContract(provider.capability === 'independent-observer', 'observer capability is false');
    const first = await provider.publish(input.fixtures.first);
    const duplicate = await provider.publish(input.fixtures.first);
    expectContract(equalJson(first, duplicate), 'duplicate checkpoint changed observation receipt');
    const next = await provider.publish(input.fixtures.next);
    expectContract(
      next.core.previousObservationDigest === first.observationDigest,
      'observation receipt chain was not linked',
    );
    const latest = await provider.latest(input.fixtures.next.core);
    expectContract(
      latest?.checkpoint.checkpointDigest === input.fixtures.next.checkpointDigest,
      'latest observed checkpoint is incorrect',
    );
  });
  await check(checks, 'rejects rollback and same-size conflicting views', async () => {
    const provider = await input.createProvider();
    await provider.publish(input.fixtures.first);
    for (const candidate of [input.fixtures.conflict, input.fixtures.rollback]) {
      let rejected = false;
      try {
        await provider.publish(candidate);
      } catch {
        rejected = true;
      }
      expectContract(rejected, 'observer accepted rollback or split view');
    }
  });
  await check(checks, 'rejects a checkpoint whose signature does not verify', async () => {
    const provider = await input.createProvider();
    expectContract(
      await refuses(provider, withBrokenSignature(input.fixtures.first)),
      'observer accepted a first checkpoint whose signature does not verify',
    );
    await provider.publish(input.fixtures.first);
    expectContract(
      await refuses(provider, withBrokenSignature(input.fixtures.next)),
      'observer accepted a larger checkpoint whose signature does not verify',
    );
    await expectLatest(provider, input.fixtures.first);
  });
  await check(checks, 'rejects a larger checkpoint that does not extend the observed tree', async () => {
    const { first, fork } = input.fixtures;
    expectContract(
      fork !== undefined,
      'fixtures.fork is required: a validly signed checkpoint, larger than fixtures.first, ' +
        'over a history that does not extend its tree',
    );
    expectContract(
      fork.core.ledgerId === first.core.ledgerId &&
        fork.core.ledgerEpochId === first.core.ledgerEpochId &&
        BigInt(fork.core.treeSize) > BigInt(first.core.treeSize),
      'fixtures.fork must be a larger checkpoint of the ledger epoch of fixtures.first',
    );
    expectContract(
      !(await refuses(await input.createProvider(), fork)),
      'observer refused fixtures.fork on its own, so its refusal after fixtures.first shows nothing',
    );
    const provider = await input.createProvider();
    await provider.publish(first);
    expectContract(
      await refuses(provider, fork),
      'observer accepted a larger checkpoint that does not extend the observed tree',
    );
    await expectLatest(provider, first);
  });
  if (input.fixtures.gapped !== undefined) {
    const gapped = input.fixtures.gapped;
    await check(checks, 'accepts a gapped but consistent extension as catch-up', async () => {
      const provider = await input.createProvider();
      const first = await provider.publish(input.fixtures.first);
      const observation = await provider.publish(gapped);
      expectContract(
        observation.core.previousObservationDigest === first.observationDigest,
        'gapped observation did not link the prior observation receipt',
      );
      const latest = await provider.latest(gapped.core);
      expectContract(
        latest?.checkpoint.checkpointDigest === gapped.checkpointDigest,
        'gapped catch-up did not become the latest observation',
      );
    });
  }
  return report('observer', checks);
}
