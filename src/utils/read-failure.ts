/**
 * Why a read of a URL failed, kept on the error the read throws in its own words, so that a caller
 * can say why without parsing the message. The reader's own rules refused the host (the
 * private-network rule or the scheme rule, on the URL or on a redirect), its deadline passed, what
 * came back held more bytes than the read allows, or it could not be read as what was asked for. An
 * error the transport throws carries none: its words are the transport's, and may say more about
 * the network than a refusal should. A refusal of the URL as given, before any request or DNS
 * lookup, says so ({@link refusedBeforeRequest}), since it tells whoever named the URL nothing the
 * network answered.
 */

/** The kind of failure a {@link ReadFailureError} stands for. */
export type ReadFailureKind = 'host_refused' | 'deadline_exceeded' | 'too_large' | 'unavailable';

/** How a {@link ReadFailureError} came about, beyond its kind. */
export interface ReadFailureOrigin {
  /** Whether the reader's rules refused the URL as given, before any request or DNS lookup. */
  readonly beforeRequest?: boolean;
}

/**
 * An error a reader throws in its own words, with the {@link ReadFailureKind} it stands for and
 * whether it refused the URL before any request or DNS lookup. Neither is enumerable, so the error
 * compares, prints and serialises as a plain `Error` with the same message does.
 */
export class ReadFailureError extends Error {
  declare readonly kind: ReadFailureKind;
  declare readonly beforeRequest: boolean;

  constructor(kind: ReadFailureKind, message: string, origin: ReadFailureOrigin = {}) {
    super(message);
    Object.defineProperty(this, 'kind', { value: kind, enumerable: false, writable: false, configurable: false });
    Object.defineProperty(this, 'beforeRequest', {
      value: origin.beforeRequest === true, enumerable: false, writable: false, configurable: false,
    });
  }
}

/** The kind of failure `error` stands for, or `undefined` for an error no reader raised in its own words. */
export function readFailureKind(error: unknown): ReadFailureKind | undefined {
  return error instanceof ReadFailureError ? error.kind : undefined;
}

/** Whether `error` is a reader's refusal of a URL as given, before any request or DNS lookup. */
export function refusedBeforeRequest(error: unknown): boolean {
  return error instanceof ReadFailureError && error.beforeRequest;
}
