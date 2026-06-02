/**
 * A2A wire-format interop codec — public surface.
 *
 * Bidirectional shape translation between foreign agent-to-agent envelopes
 * (Google A2A, Adobe A2A) and the canonical KYA-OS `DelegationRecord`, plus
 * structural format detection. No signature verification, no DID resolution, no
 * vendor SDK dependency — the codec only normalizes shape so the gateway can land
 * any vendor envelope on the existing verify/attenuate/audience path.
 */
export * from './a2a-types.js';
export * from './google-a2a-adapter.js';
export * from './adobe-a2a-adapter.js';
export * from './detect.js';
