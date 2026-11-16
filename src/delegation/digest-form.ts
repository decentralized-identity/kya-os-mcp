/**
 * The form a digest is written in (SPEC.md §7.8): `sha256:` followed by 64
 * lowercase hex characters. A chain digest is taken over credential digests
 * in this form, and a reference in this form is the digest of an id.
 *
 * Pure: no transport, no framework, no key material.
 */

import type { Digest } from '../audit/types.js';

const DIGEST = /^sha256:[a-f0-9]{64}$/;

/** Whether a value reads as a digest: `sha256:` followed by 64 lowercase hex characters. */
export function isDigest(value: unknown): value is Digest {
  return typeof value === 'string' && DIGEST.test(value);
}
