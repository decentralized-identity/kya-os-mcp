/**
 * Graph Node Turns
 *
 * Each change a `DelegationGraphManager` makes to a stored node reads the node and writes it back
 * whole, so two changes to one node at once would lose one. Each takes its turn at the node, in a
 * lock every manager over one storage provider object shares, and waits for it at most
 * {@link NODE_TURN_WAIT_MS}: a change behind a write the store never finishes then throws, having
 * changed nothing, rather than wait forever.
 */

import { describeTimeout } from '../utils/deadline.js';
import { describeValue } from '../utils/describe-value.js';
import { keyedLockOf, LONGEST_WAIT_MS } from '../utils/keyed-lock.js';
import { RefusalError } from '../utils/refusal.js';

/** The longest a change to a node waits for its turn, in milliseconds: the longest one wait of a status list write. */
export const NODE_TURN_WAIT_MS = LONGEST_WAIT_MS;

/** The turns at the nodes of one graph store. */
export interface NodeTurns {
  /**
   * Run `task`, which makes the change `change` describes to the node of `delegationId`, in that
   * node's turn, and settle as it does. `change` completes "Delegation X was not ...".
   *
   * @throws {RefusalError} of code `deadline_exceeded`, which is transient, naming the node, when
   *   the turn has not come within {@link NODE_TURN_WAIT_MS}: `task` never ran, so make the change again.
   */
  take<T>(delegationId: string, change: string, task: () => Promise<T>): Promise<T>;
}

/** The turns at the nodes of `storage`, shared with every manager over that object. */
export function nodeTurnsOf(storage: object): NodeTurns {
  const lock = keyedLockOf(storage);
  return {
    take: (delegationId, change, task) =>
      lock.run(delegationId, task, {
        ms: NODE_TURN_WAIT_MS,
        expired: () => stalledTurn(delegationId, change),
      }),
  };
}

/** The error of a change to the node of `delegationId` whose turn did not come. */
function stalledTurn(delegationId: string, change: string): RefusalError {
  return new RefusalError(
    'deadline_exceeded',
    `Delegation ${describeValue(delegationId)} was not ${change}: another change to its node in the graph did not ` +
      `finish within ${describeTimeout(NODE_TURN_WAIT_MS)}, so this change never got its turn and changed nothing. ` +
      'Make it again',
  );
}

/** Whether `error` is a change to a node whose turn did not come, which making it again may land. */
export function isStalledTurn(error: unknown): error is RefusalError {
  return error instanceof RefusalError && error.code === 'deadline_exceeded';
}
