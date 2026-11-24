/**
 * The KYA-OS protocol version (SPEC.md §13): `MAJOR.MINOR`, two decimal integers joined by a dot.
 */

import { KYA_OS_ERROR_CODES } from "../errors.js";
import { describeValue } from "../utils/describe-value.js";

/** The version this implementation speaks, which every handshake response states. */
export const KYA_OS_PROTOCOL_VERSION = "1.0";

const MAJOR = 1;

/** `MAJOR.MINOR`, or for the 1.x line the `MAJOR.MINOR.PATCH` form SPEC.md §13 once told clients to send. */
const STATED_VERSION = /^(\d+)\.\d+(?:\.\d+)?$/;

/**
 * Whether a server of this version serves a handshake whose `clientProtocolVersion` is `stated`:
 * one of this major version is served whatever its minor, and one of another major version is
 * refused. One that states none is of 1.0. For the 1.x line a value that is not a version is read
 * as none, as 1.26.0 and earlier read every value; 2.0.0 refuses it.
 */
export function speaksProtocolVersion(stated: unknown): boolean {
  const match = typeof stated === "string" ? STATED_VERSION.exec(stated) : null;
  return match === null || Number(match[1]) === MAJOR;
}

/**
 * The refusal of a handshake whose `clientProtocolVersion` is `stated`, or `undefined` when a
 * server of this version serves it. A server checks this before anything else of the request.
 */
export function protocolVersionRefusal(stated: unknown):
  | { code: typeof KYA_OS_ERROR_CODES.protocol_version_unsupported; message: string; remediation: string }
  | undefined {
  if (speaksProtocolVersion(stated)) return undefined;
  return {
    code: KYA_OS_ERROR_CODES.protocol_version_unsupported,
    message: `This server speaks KYA-OS ${KYA_OS_PROTOCOL_VERSION}; the handshake states clientProtocolVersion ${describeValue(stated)}`,
    remediation: `Send clientProtocolVersion "${KYA_OS_PROTOCOL_VERSION}", or leave it out`,
  };
}
