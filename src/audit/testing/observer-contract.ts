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
