/**
 * Test helper: the small encodings tests write their inputs with.
 */

/** `data` as base64url without padding, text as its UTF-8: how a JWS writes a segment. */
export const base64url = (data: Uint8Array | string): string => Buffer.from(data).toString('base64url');

/** The string of the one UTF-16 code unit `code`. */
export const unit = (code: number): string => String.fromCharCode(code);
