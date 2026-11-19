import { describe, expect, it } from 'vitest';
import type { AuditCheckpointObserverProvider } from '../providers/observer.js';
import { evaluateAuditObserverProviderContract } from '../testing/provider-contracts.js';
import type { SignedAuditCheckpointV1 } from '../types.js';
import { checkingObserver, observerContractFixtures } from './observer-fixtures.js';

const signatureCheck = 'rejects a checkpoint whose signature does not verify';
const forkCheck = 'rejects a larger checkpoint that does not extend the observed tree';

type Report = Awaited<ReturnType<typeof evaluateAuditObserverProviderContract>>;

function checkOf(report: Report, name: string) {
  return report.checks.find((item) => item.name === name);
}

function errorOf(report: Report, name: string): string {
  return String((checkOf(report, name)?.error as Error | undefined)?.message);
}

describe('observer provider contract: what an observer signs', () => {
  it('passes an observer that checks each checkpoint signature and each extension', async () => {
    const { fixtures, builders } = await observerContractFixtures();
    const report = await evaluateAuditObserverProviderContract({
      fixtures, createProvider: () => checkingObserver(builders),
    });
    expect(report.checks.filter((item) => !item.passed)).toEqual([]);
    expect(report.checks.map((item) => item.name)).toEqual(expect.arrayContaining([signatureCheck, forkCheck]));
    expect(report.passed).toBe(true);
  });

  it('fails an observer that signs a larger checkpoint without checking it extends the observed tree', async () => {
    const { fixtures, builders } = await observerContractFixtures();
    const report = await evaluateAuditObserverProviderContract({
      fixtures, createProvider: () => checkingObserver(builders, { verifyConsistency: async () => true }),
    });
    expect(checkOf(report, forkCheck)).toMatchObject({ passed: false });
    expect(errorOf(report, forkCheck)).toMatch(/does not extend/);
    expect(checkOf(report, signatureCheck)).toMatchObject({ passed: true });
    expect(report.passed).toBe(false);
  });

  it('fails an observer that signs a checkpoint without checking its signature', async () => {
    const { fixtures, builders } = await observerContractFixtures();
    const report = await evaluateAuditObserverProviderContract({
      fixtures, createProvider: () => checkingObserver(builders, { verifyCheckpoint: async () => true }),
    });
    expect(checkOf(report, signatureCheck)).toMatchObject({ passed: false });
    expect(errorOf(report, signatureCheck)).toMatch(/signature does not verify/);
    expect(report.passed).toBe(false);
  });

  it('fails when no fork fixture is given, since nothing else can show the extension check', async () => {
    const { fixtures, builders } = await observerContractFixtures();
    const { fork: _fork, ...withoutFork } = fixtures;
    const report = await evaluateAuditObserverProviderContract({
      fixtures: withoutFork, createProvider: () => checkingObserver(builders),
    });
    expect(checkOf(report, forkCheck)).toMatchObject({ passed: false });
    expect(errorOf(report, forkCheck)).toMatch(/fixtures\.fork is required/);
  });

  it('fails a fork fixture that is not larger than first, rather than pass the check vacuously', async () => {
    const { fixtures, builders } = await observerContractFixtures();
    const report = await evaluateAuditObserverProviderContract({
      fixtures: { ...fixtures, fork: fixtures.conflict },
      createProvider: () => checkingObserver(builders),
    });
    expect(errorOf(report, forkCheck)).toMatch(/larger checkpoint of the ledger epoch of fixtures\.first/);
  });

  it('fails a fork fixture the observer refuses on its own, since it shows nothing about extension', async () => {
    const { fixtures, builders } = await observerContractFixtures();
    const unsigned: SignedAuditCheckpointV1 = { ...fixtures.fork, jws: 'not.a.signature' };
    const report = await evaluateAuditObserverProviderContract({
      fixtures: { ...fixtures, fork: unsigned },
      createProvider: () => checkingObserver(builders),
    });
    expect(errorOf(report, forkCheck)).toMatch(/refused fixtures\.fork on its own/);
  });

  it('fails an observer that keeps a refused checkpoint as its latest observation', async () => {
    const { fixtures, builders } = await observerContractFixtures();
    // Refuses the publication but has already taken the checkpoint as the one it observed.
    const careless = (): AuditCheckpointObserverProvider => {
      const inner = checkingObserver(builders);
      let latest: SignedAuditCheckpointV1 | undefined;
      return {
        capability: 'independent-observer',
        publish: async (checkpoint) => {
          latest = checkpoint;
          return inner.publish(checkpoint);
        },
        latest: async (ref) => {
          const observed = await inner.latest(ref);
          return observed === null || latest === undefined ? observed : { ...observed, checkpoint: latest };
        },
        verifyObservation: (checkpoint, receipt) => inner.verifyObservation(checkpoint, receipt),
      };
    };
    const report = await evaluateAuditObserverProviderContract({ fixtures, createProvider: careless });
    expect(errorOf(report, forkCheck)).toMatch(/latest observation/);
    expect(errorOf(report, signatureCheck)).toMatch(/latest observation/);
  });
});
