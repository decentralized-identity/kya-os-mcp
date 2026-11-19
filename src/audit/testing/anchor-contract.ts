import type { AuditAnchorProvider } from '../providers/anchor.js';
import type { SignedAuditCheckpointV1 } from '../types.js';
import {
  check,
  expectContract,
  report,
  type AuditProviderContractCheck,
  type AuditProviderContractReport,
} from './contract-harness.js';

/** Executable role-separation and binding contract for supporting anchors. */
export async function evaluateAuditAnchorProviderContract(input: {
  createProvider(): AuditAnchorProvider | Promise<AuditAnchorProvider>;
  checkpoint: SignedAuditCheckpointV1;
  otherCheckpoint: SignedAuditCheckpointV1;
}): Promise<AuditProviderContractReport> {
  const checks: AuditProviderContractCheck[] = [];
  await check(checks, 'publishes and verifies only a checkpoint-bound supporting receipt', async () => {
    const provider = await input.createProvider();
    expectContract(provider.capability === 'supporting-anchor', 'anchor claimed observer capability');
    const receipt = await provider.publish(input.checkpoint);
    expectContract(receipt.kind === provider.kind, 'anchor kind mismatch');
    expectContract(receipt.checkpointDigest === input.checkpoint.checkpointDigest, 'receipt is unbound');
    expectContract(await provider.verify(input.checkpoint, receipt), 'valid receipt did not verify');
    expectContract(
      !(await provider.verify(input.otherCheckpoint, receipt)),
      'receipt verified for a different checkpoint',
    );
  });
  return report('anchor', checks);
}
