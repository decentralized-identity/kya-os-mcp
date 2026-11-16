import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

/**
 * The schemas in `schemas/` are published at schema.kya-os.org under their `$id`, and a
 * published `$id` never changes its bytes. `published-schemas.json` records the bytes each
 * `$id` is published with, so a change to a schema that keeps its `$id` fails here, before
 * it ships, rather than when kya-os-schema refuses it at publication.
 */

const SCHEMAS_DIR = new URL('../../schemas/', import.meta.url);
const CANONICAL_ID = /^https:\/\/schema\.kya-os\.org\/v1\/protocol\/[a-z0-9-]+(?:\/[a-z0-9-]+)*\/v\d+\.\d+\.\d+$/;

interface SchemaFile {
  readonly name: string;
  readonly id: string;
  readonly digest: string;
}

function schemaFiles(): SchemaFile[] {
  return readdirSync(SCHEMAS_DIR)
    .filter((name) => name.endsWith('.json'))
    .sort()
    .map((name) => {
      const bytes = readFileSync(new URL(name, SCHEMAS_DIR));
      const { $id } = JSON.parse(bytes.toString('utf8')) as { $id?: unknown };
      if (typeof $id !== 'string') throw new Error(`schemas/${name} states no $id`);
      return { name, id: $id, digest: createHash('sha256').update(bytes).digest('hex') };
    });
}

const published = (
  JSON.parse(readFileSync(new URL('published-schemas.json', import.meta.url), 'utf8')) as {
    schemas: Record<string, string>;
  }
).schemas;

describe('published schemas', () => {
  const files = schemaFiles();

  it('finds the schemas', () => {
    expect(files.length).toBeGreaterThan(0);
  });

  it.each(files)('schemas/$name has a canonical, versioned $id of its own', ({ name, id }) => {
    expect(id, `schemas/${name}`).toMatch(CANONICAL_ID);
    expect(files.filter((other) => other.id === id).map((other) => other.name)).toEqual([name]);
  });

  it.each(files)('schemas/$name keeps the bytes its $id is published with', ({ name, id, digest }) => {
    const recorded = published[id];
    if (recorded === undefined) {
      expect.fail(
        `schemas/${name} has an $id that is not recorded: add "${id}": "${digest}" to ` +
          'src/__tests__/published-schemas.json',
      );
    }
    if (recorded !== digest) {
      expect.fail(
        `schemas/${name} changed under ${id}, which is published with other bytes. ` +
          'Give the schema a new version in its $id and record that $id. ' +
          'A change that only widens what the schema accepts may keep its $id: then update its digest ' +
          "and record the widening in kya-os-schema's in-place-transitions.json.",
      );
    }
  });

  it('records only canonical $ids and SHA-256 digests', () => {
    for (const [id, digest] of Object.entries(published)) {
      expect(id).toMatch(CANONICAL_ID);
      expect(digest, id).toMatch(/^[0-9a-f]{64}$/);
    }
  });
});
