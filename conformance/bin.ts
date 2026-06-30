#!/usr/bin/env node
/**
 * KYA-OS conformance harness CLI.
 *
 * Loads the bundled vectors, runs them through the reference adapter (or a
 * filtered subset), prints the report, and exits non-zero on ANY mismatch — so a
 * single tampered proof that the implementation fails to reject breaks CI.
 *
 * Usage:
 *   tsx conformance/bin.ts                 # run all vectors (reference adapter)
 *   tsx conformance/bin.ts --category signed-proof
 *   tsx conformance/bin.ts --json          # machine-readable report
 *
 * Third parties: import { runConformance } from './runner.js' and pass your own
 * ConformanceAdapter. See CONFORMANCE.md.
 */

import { Command } from 'commander';
import { loadVectors } from './loader.js';
import { runConformance, formatReport } from './runner.js';
import { ReferenceConformanceAdapter } from './reference-adapter.js';
import type { VectorCategory } from './types.js';

const program = new Command();

program
  .name('kya-os-conformance')
  .description('Run the KYA-OS protocol conformance vectors against the reference implementation')
  .option('-c, --category <category>', 'only run vectors in this category')
  .option('--json', 'emit a machine-readable JSON report')
  .action(async (opts: { category?: string; json?: boolean }) => {
    let vectors = loadVectors();
    if (opts.category) {
      vectors = vectors.filter((v) => v.category === (opts.category as VectorCategory));
      if (vectors.length === 0) {
        console.error(`No vectors found for category "${opts.category}"`);
        process.exit(2);
      }
    }

    const report = await runConformance(new ReferenceConformanceAdapter(), vectors);

    if (opts.json) {
      console.log(JSON.stringify(report, null, 2));
    } else {
      console.log(formatReport(report));
    }

    process.exit(report.allMatched ? 0 : 1);
  });

program.parseAsync(process.argv).catch((error) => {
  console.error(`Conformance runner error: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(2);
});
