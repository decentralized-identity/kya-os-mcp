/**
 * Shared fail-closed status-list `statusPurpose` check — the SINGLE source of truth for the
 * invariant both the card revocation reader (`src/card/revocation.ts`) and the delegation status
 * manager (`src/delegation/statuslist-manager.ts`) enforce, so the two readers cannot drift.
 */

/**
 * Fail CLOSED unless the resolved status list's `statusPurpose` is present AND equals `wanted`. A
 * list of a DIFFERENT kind (e.g. a `suspension` list read as `revocation`) must not be accepted —
 * its clear bit would otherwise report "not revoked" from the wrong list, a fail-open bypass.
 */
export function assertStatusPurpose(listPurpose: unknown, wanted: string): void {
  if (typeof listPurpose !== 'string') {
    throw new Error(`status list has no statusPurpose (expected "${wanted}") — fail-closed`);
  }
  if (listPurpose !== wanted) {
    throw new Error(`status list statusPurpose mismatch: "${listPurpose}" ≠ "${wanted}"`);
  }
}
