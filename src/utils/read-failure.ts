/**
 * Why a read of a URL failed, kept on the error the read throws in its own words, so that a caller
 * can say why without parsing the message. The reader's own rules refused the host (the
 * private-network rule or the scheme rule, on the URL or on a redirect), its deadline passed, what
 * came back held more bytes than the read allows, or it could not be read as what was asked for. An
 * error the transport throws carries none: its words are the transport's, and may say more about
 * the network than a refusal should.
 */

/** The kind of failure a {@link ReadFailureError} stands for. */
export type ReadFailureKind = 'host_refused' | 'deadline_exceeded' | 'too_large' | 'unavailable';

/**
 * An error a reader throws in its own words, with the {@link ReadFailureKind} it stands for. The
 * kind is not enumerable, so the error compares, prints and serialises as a plain `Error` with the
 * same message does.
 */
export class ReadFailureError extends Error {
  declare readonly kind: ReadFailureKind;

  constructor(kind: ReadFailureKind, message: string) {
    super(message);
    Object.defineProperty(this, 'kind', { value: kind, enumerable: false, writable: false, configurable: false });
  }
}

/** The kind of failure `error` stands for, or `undefined` for an error no reader raised in its own words. */
export function readFailureKind(error: unknown): ReadFailureKind | undefined {
  return error instanceof ReadFailureError ? error.kind : undefined;
}
