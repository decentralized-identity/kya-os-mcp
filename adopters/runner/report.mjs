/**
 * The summary a run ends with: per fixture its type errors, whether it passed, and the first line
 * that says why not; then every type error and every failed case in full.
 */

/** `text` padded to `width` columns. */
const pad = (text, width) => String(text).padEnd(width);

/** The number of type errors `owner` has. */
const errorCount = (typeErrors, owner) => typeErrors.get(owner)?.length ?? 0;

/** Print the summary of `results` and `typeErrors` for the packed `library`. Returns whether all passed. */
export function printSummary({ library, results, typeErrors }) {
  const width = Math.max(...results.map((result) => result.name.length), 'fixture'.length) + 2;
  console.log(`\nAdopter fixtures against ${library} on Node ${process.version}\n`);
  console.log(`  ${pad('fixture', width)}${pad('types', 8)}${pad('result', 8)}first failure`);
  for (const result of results) {
    const failure = result.firstFailure?.replace(`FAIL ${result.name}: `, '') ?? '';
    console.log(`  ${pad(result.name, width)}${pad(errorCount(typeErrors, result.name), 8)}${pad(result.passed ? 'pass' : 'FAIL', 8)}${failure}`);
  }
  for (const owner of ['shared', 'project']) {
    if (typeErrors.has(owner)) console.log(`  ${pad(owner, width)}${pad(errorCount(typeErrors, owner), 8)}`);
  }

  const allTypeErrors = [...typeErrors.values()].flat();
  if (allTypeErrors.length > 0) {
    console.log('\nType errors:');
    for (const error of allTypeErrors) console.log(`  ${error.replaceAll('\n', '\n  ')}`);
  }
  const failed = results.filter((result) => !result.passed);
  if (failed.length > 0) {
    console.log('\nFailed cases:');
    for (const result of failed) {
      for (const line of result.failures.length > 0 ? result.failures : [`FAIL ${result.name}: ${result.firstFailure}`]) {
        console.log(`  ${line}`);
      }
    }
  }
  const passed = failed.length === 0 && allTypeErrors.length === 0;
  console.log(`\n${passed ? 'All adopter fixtures pass.' : `${failed.length} of ${results.length} fixtures failed, with ${allTypeErrors.length} type errors.`}`);
  return passed;
}
