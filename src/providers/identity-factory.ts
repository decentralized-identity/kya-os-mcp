/**
 * Identity provisioning helpers
 *
 * Compose a {@link CryptoProvider} with the appropriate DID method to
 * mint a fresh {@link Identity} in a single call. The package
 * previously exposed the lower-level primitives
 * (`CryptoProvider.generateKeyPair`, `generateDidKeyFromBase64`) but
 * no high-level "issue an identity" shortcut — every consumer ended
 * up writing roughly the same wrapper.
 *
 * Both helpers return a {@link ProvisionedIdentity}: an `Identity` with
 * `privateKey` narrowed to required, since the helper itself produced
 * the key material and the contract guarantees it is present.
 *
 * ## Public surfaces
 *
 *   - {@link createDidKeyIdentity} — method-specific shortcut for did:key
 *   - {@link createDidWebIdentity} — method-specific shortcut for did:web
 *   - {@link createIdentity}       — dispatching surface (discriminated
 *     union over `method`) for callers that want to parameterise the
 *     DID method or for forward-compatibility with did:jwk / did:peer /
 *     did:ion as those land. New methods extend this dispatcher
 *     without growing the top-level export surface.
 *
 * Related Spec: MCP-I §3 (Protocol Overview), §4 (Agent Identity),
 * §4.3 (did:key Derivation — the normative `<did>#keys-1`
 * verification-method-id statement lives here), §4.4 (did:web
 * Resolution); CONFORMANCE.md §3 (Key ID format). See
 * `delegation/did-web-resolver.ts#buildDidWebDocument` for the
 * companion that publishes the resulting did:web DID Document.
 *
 * ## Design notes for downstream ports (Rust / Go / Python / …)
 *
 * The implementation makes four protocol-level choices the spec
 * either leaves open or is internally inconsistent about. Each is
 * called out here so a competing implementation can mirror them
 * faithfully — or argue against them at TAAWG — without re-deriving
 * the reasoning from source.
 *
 * 1. **did:web verification-method-id default = `<did>#keys-1`.**
 *    SPEC.md is internally inconsistent: line 177 normatively states
 *    `<did>#keys-1` (matched by CONFORMANCE.md:43 and the did:key
 *    examples at lines 344, 885, 896), but the did:web examples at
 *    lines 125, 194, 203, 204, 498, 528 use `<did>#key-1` (singular).
 *    This helper picks `keys-1` because (a) it matches the normative
 *    line-177 statement, (b) it matches CONFORMANCE.md, and (c) it
 *    keeps did:key and did:web symmetric. A working-group decision
 *    is required before 1.0 to resolve the inconsistency — once
 *    resolved, flip {@link DEFAULT_DID_WEB_KID_FRAGMENT} and update
 *    CONFORMANCE.md / SPEC.md to match.
 *
 * 2. **Path segments are NOT auto-percent-encoded.** The helper
 *    rejects raw `/` and `:` rather than escaping them silently.
 *    Rationale: silent escaping changes the DID the caller intended,
 *    which is harmful in identity-protocol semantics where the DID
 *    is the identifier. Callers who want to include reserved bytes
 *    must pass them already-encoded. This trades convenience for
 *    determinism and matches the existing behaviour of
 *    `parseDidWeb` / `didWebToUrl` in this repo.
 *
 * 3. **`metadata` is deep-cloned via `structuredClone`.** Threat
 *    model: a caller passes a metadata object, retains a reference,
 *    later mutates a nested value (e.g. a policy bag or a counter),
 *    and the produced Identity silently shifts under their feet —
 *    or worse, two long-lived Identities share aliased state. Deep
 *    cloning eliminates the aliasing. Cost is one O(n) traversal at
 *    creation; n is small in practice.
 *
 * 4. **`kidFragment` is configurable on did:web but not did:key.**
 *    Per W3C CCG did:key §3 (Document Creation Algorithm) the
 *    fragment is fixed to the multibase id of the public key — so
 *    there is no configurable choice for did:key. did:web makes no
 *    such determination; the fragment is whatever the DID Document
 *    declares, so the helper exposes a single configurable knob.
 *    The asymmetry is required by the specs, not a stylistic one.
 */

import type { ClockProvider, CryptoProvider, Identity } from './base.js';
import {
  didKeyFragment,
  generateDidKeyFromBase64,
} from '../utils/did-helpers.js';

/**
 * Default verification-method fragment for fresh did:web identities.
 *
 * See "Design notes" §1 in the file header for the rationale on
 * `keys-1` vs `key-1`. The spec is internally inconsistent and a
 * TAAWG decision is pending; this default flips trivially once that
 * decision lands.
 */
const DEFAULT_DID_WEB_KID_FRAGMENT = 'keys-1';

/**
 * Maximum length of caller-supplied input echoed back in a thrown
 * error message before truncation. Keeps log output bounded and
 * limits the bytes an attacker can spray through error pipelines.
 */
const ERROR_ECHO_MAX_LENGTH = 60;

/**
 * RFC 3986 `fragment` grammar — `*( pchar / "/" / "?" )` where
 * `pchar = unreserved / pct-encoded / sub-delims / ":" / "@"`.
 *
 * Excludes `"#"` (one fragment delimiter per URI), whitespace, and
 * control characters. Used to validate caller-supplied `kidFragment`
 * values so the produced verification-method id is well-formed.
 *
 * @see RFC 3986 §3.5
 */
const RFC3986_FRAGMENT_PATTERN =
  /^(?:[A-Za-z0-9\-._~!$&'()*+,;=:@/?]|%[0-9A-Fa-f]{2})+$/;

/**
 * An {@link Identity} that carries its private-key material.
 *
 * Returned by the provisioning helpers: they mint the key, so the
 * field is always present and callers do not need to narrow before
 * signing.
 */
export type ProvisionedIdentity = Identity & { privateKey: string };

/**
 * Options shared by both provisioning helpers.
 */
export interface CreateIdentityOptions {
  /**
   * Clock used to stamp `createdAt`. Defaults to the host wall clock.
   * Inject in tests for deterministic timestamps.
   */
  clock?: ClockProvider;
  /** Free-form metadata to attach to the produced Identity. */
  metadata?: Record<string, unknown>;
}

/**
 * Options for {@link createDidWebIdentity}.
 */
export interface CreateDidWebIdentityOptions extends CreateIdentityOptions {
  /**
   * Verification-method fragment used to build the produced Identity's
   * `kid` (`<did>#<fragment>`). Defaults to `keys-1`.
   *
   * Set this when the DID Document published at the resolution URL
   * declares a non-default fragment, so the produced Identity's `kid`
   * round-trips through the resolver cleanly.
   */
  kidFragment?: string;
}

/**
 * Arguments for {@link createDidWebIdentity}.
 */
export interface CreateDidWebIdentityArgs {
  /**
   * did:web authority component (host or host:port). The port, when
   * present, must be percent-encoded as `%3A` per did:web encoding
   * rules (e.g. `example.com%3A8080`).
   *
   * Must not include a scheme prefix or any `/` — pass path segments
   * via {@link CreateDidWebIdentityArgs.path}.
   */
  domain: string;

  /**
   * Optional path segments appended after the authority. The produced
   * DID resolves to `https://<domain>/<segment>/.../did.json` (see
   * `didWebToUrl`).
   *
   * @example
   * `{ domain: 'example.com', path: ['users', 'alice'] }`
   * → `did:web:example.com:users:alice`
   * → `https://example.com/users/alice/did.json`
   */
  path?: readonly string[];
}

/**
 * Mint a fresh `did:key` Identity using the supplied
 * {@link CryptoProvider}.
 *
 * Generates an Ed25519 key pair, derives the did:key encoding, and
 * bundles the pieces into an Identity. The returned object carries
 * the private key in plain memory; the **caller is responsible for
 * routing it to a wallet / HSM / KMS and wiping the in-memory copy**
 * once it has been persisted. The helper itself performs no key
 * zeroisation — string immutability prevents reliable wiping in
 * JavaScript.
 *
 * @throws Error if the supplied {@link CryptoProvider} fails to
 *   produce a key pair, or if {@link CreateIdentityOptions.metadata}
 *   contains values that cannot be structurally cloned (functions,
 *   DOM nodes, host-bound objects).
 *
 * @example
 * ```typescript
 * const identity = await createDidKeyIdentity(new NodeCryptoProvider());
 * // identity.did === 'did:key:z6Mk...'
 * // identity.kid === `${identity.did}#${didKeyFragment(identity.did)}`
 * ```
 */
export async function createDidKeyIdentity(
  crypto: CryptoProvider,
  options?: CreateIdentityOptions
): Promise<ProvisionedIdentity> {
  const metadata = cloneMetadata(options?.metadata);
  const { publicKey, privateKey } = await crypto.generateKeyPair();
  const did = generateDidKeyFromBase64(publicKey);
  const kid = `${did}#${didKeyFragment(did)}`;
  return {
    did,
    kid,
    publicKey,
    privateKey,
    createdAt: nowIso(options?.clock),
    ...(metadata !== undefined ? { metadata } : {}),
  };
}

/**
 * Mint a fresh `did:web` Identity for a subject hosted under a domain.
 *
 * Produces `did:web:<domain>[:<path1>[:<path2>...]]` bound to a
 * freshly generated Ed25519 key. The caller is responsible for
 * publishing the resulting DID Document at the resolution URL — pair
 * with `buildDidWebDocument` and `didWebToUrl`.
 *
 * Same private-key responsibility as {@link createDidKeyIdentity}:
 * the returned object carries the private key in plain memory and
 * the caller must route it onward.
 *
 * Validates `domain`, `path` segments, and `kidFragment` at call time
 * per the repository's construction-throws contract: invalid input
 * fails before any key material is generated.
 *
 * @throws Error if `args.path` is supplied but is not an array.
 * @throws Error if `args.domain` is empty, includes a scheme prefix,
 *   contains a literal `/` or `:`, contains invalid or incomplete
 *   percent-encoding, decodes to a value containing `/`, `\`, or NUL,
 *   decodes to a malformed hostname (per RFC 952 / RFC 1123 — empty
 *   labels, leading/trailing hyphens, oversize labels or total
 *   length), or decodes to an invalid port (per RFC 3986 §3.2.3).
 * @throws Error if any `args.path` segment is empty, contains a
 *   literal `:` or `/`, contains invalid percent-encoding, or
 *   decodes to a relative path component (`.` / `..`), `/`, `\`, or
 *   NUL.
 * @throws Error if `options.kidFragment` is empty or contains
 *   characters outside the RFC 3986 fragment grammar.
 * @throws Error if {@link CreateIdentityOptions.metadata} contains
 *   values that cannot be structurally cloned (functions, DOM nodes,
 *   host-bound objects).
 * @throws Error if the supplied {@link CryptoProvider} fails to
 *   produce a key pair.
 *
 * @example
 * ```typescript
 * const identity = await createDidWebIdentity(crypto, {
 *   domain: 'example.com',
 *   path: ['users', 'alice'],
 * });
 * // identity.did === 'did:web:example.com:users:alice'
 * // identity.kid === 'did:web:example.com:users:alice#keys-1'
 * ```
 */
export async function createDidWebIdentity(
  crypto: CryptoProvider,
  args: CreateDidWebIdentityArgs,
  options?: CreateDidWebIdentityOptions
): Promise<ProvisionedIdentity> {
  const domain = validateDidWebDomain(args.domain);
  const segments = validatePath(args.path);
  const did =
    segments.length === 0
      ? `did:web:${domain}`
      : `did:web:${domain}:${segments.join(':')}`;
  const fragment =
    options?.kidFragment !== undefined
      ? validateDidWebKidFragment(options.kidFragment)
      : DEFAULT_DID_WEB_KID_FRAGMENT;
  const kid = `${did}#${fragment}`;

  const metadata = cloneMetadata(options?.metadata);
  const { publicKey, privateKey } = await crypto.generateKeyPair();

  return {
    did,
    kid,
    publicKey,
    privateKey,
    createdAt: nowIso(options?.clock),
    ...(metadata !== undefined ? { metadata } : {}),
  };
}

/**
 * Supported DID methods. Extend this union (and the corresponding
 * branch in {@link createIdentity}) when adding a new method-specific
 * helper.
 */
export type CreateIdentityMethod = 'did:key' | 'did:web';

/**
 * Discriminated-union request shape for {@link createIdentity}.
 *
 * The `method` field selects the per-method members — both the args
 * (e.g. `domain` / `path` for did:web) and the options
 * (`kidFragment` only on the did:web branch).
 *
 * The shape pulls options into the request itself rather than into a
 * separate parameter. This is deliberate: it lets TypeScript reject
 * did:key requests that try to pass a `kidFragment` at compile time
 * (the field does not exist on the did:key branch), rather than the
 * helper silently ignoring it at runtime. The W3C CCG did:key
 * specification fixes the verification-method fragment to the
 * multibase public-key id; allowing a caller to attempt an override
 * would violate that contract — surfacing it as a type error keeps
 * the public surface honest.
 */
export type CreateIdentityRequest =
  | ({ method: 'did:key' } & CreateIdentityOptions)
  | ({ method: 'did:web' } & CreateDidWebIdentityArgs &
      CreateDidWebIdentityOptions);

/**
 * Mint a fresh Identity, choosing the DID method at call time rather
 * than at import time.
 *
 * This is the forward-compatible surface: when did:jwk / did:peer /
 * did:ion land, they extend the {@link CreateIdentityMethod} union and
 * gain a branch on {@link CreateIdentityRequest} here, without growing
 * the top-level export footprint. Method-specific shortcuts
 * ({@link createDidKeyIdentity}, {@link createDidWebIdentity}) remain
 * available for callers that prefer a fixed surface — both routes
 * produce the same {@link ProvisionedIdentity}.
 *
 * The single-`request` argument shape (vs the more conventional
 * `(args, options)` split) is intentional: bundling per-method
 * options into the discriminated request lets the type system reject
 * cross-method misuse at compile time. See the JSDoc on
 * {@link CreateIdentityRequest} for the rationale.
 *
 * @throws Error — see {@link createDidKeyIdentity} and
 *   {@link createDidWebIdentity} for the per-method rejection
 *   contracts. All construction-throws semantics apply.
 *
 * @example
 * ```typescript
 * const a = await createIdentity(crypto, { method: 'did:key' });
 * const b = await createIdentity(crypto, {
 *   method: 'did:web',
 *   domain: 'example.com',
 *   path: ['users', 'alice'],
 *   kidFragment: 'keys-1',
 * });
 * ```
 */
export async function createIdentity(
  crypto: CryptoProvider,
  request: CreateIdentityRequest
): Promise<ProvisionedIdentity> {
  switch (request.method) {
    case 'did:key': {
      // Strip the discriminator before forwarding to the per-method
      // helper. The remaining fields satisfy CreateIdentityOptions
      // by construction of the union branch.
      const { clock, metadata } = request;
      return createDidKeyIdentity(crypto, { clock, metadata });
    }
    case 'did:web': {
      const { domain, path, clock, metadata, kidFragment } = request;
      return createDidWebIdentity(
        crypto,
        { domain, path },
        { clock, metadata, kidFragment }
      );
    }
  }
}

/* ------------------------------ internals ------------------------------ */

/**
 * Validate a did:web authority component (`domain`).
 *
 * Defence-in-depth: a permissive character-class regex is not enough.
 * `%2F` decodes to `/` (path traversal), `%00` to NUL (URL-parser
 * confusion), `..` short-circuits hostname semantics, and bare `%`
 * or incomplete escapes (`%G1`) are accepted by lax regexes but
 * break resolvers downstream. We therefore:
 *
 *   1. Reject unencoded delimiters that resolvers depend on (`:`, `/`).
 *   2. Percent-decode the input — catching invalid escapes here at
 *      construction time rather than letting the resolver discover
 *      the problem.
 *   3. Reject decoded forms that would change path semantics (`/`,
 *      `\`, NUL, leading/trailing `.`).
 *   4. Re-validate the decoded authority against the RFC 3986
 *      `reg-name [: port]` grammar (DNS-style hostname with optional
 *      port; IPv4 falls out of the same grammar; IPv6 is not
 *      currently supported in this helper).
 *
 * @see RFC 3986 §3.2.2 (host), RFC 952 / RFC 1123 (hostname labels)
 */
function validateDidWebDomain(input: string): string {
  if (input.length === 0) {
    throw new Error('createDidWebIdentity: domain must not be empty');
  }
  if (/^https?:\/\//i.test(input)) {
    throw new Error(
      'createDidWebIdentity: domain must not include a scheme prefix'
    );
  }
  if (input.includes('/')) {
    throw new Error(
      'createDidWebIdentity: domain must not contain "/"; pass path segments via the "path" option'
    );
  }
  if (input.includes(':')) {
    throw new Error(
      'createDidWebIdentity: domain must not contain ":"; percent-encode ports as "%3A"'
    );
  }

  let decoded: string;
  try {
    decoded = decodeURIComponent(input);
  } catch {
    throw new Error(
      `createDidWebIdentity: domain "${sanitizeForError(input)}" contains an invalid percent-encoded byte sequence`
    );
  }

  if (
    decoded.includes('/') ||
    decoded.includes('\\') ||
    decoded.includes('\0')
  ) {
    throw new Error(
      `createDidWebIdentity: domain "${sanitizeForError(input)}" decodes to a value containing "/", "\\", or NUL`
    );
  }

  const colonIdx = decoded.indexOf(':');
  // Multi-colon must be checked before the port check; otherwise an
  // input like `a%3Ab%3Ac` short-circuits on the port regex (digits
  // only) and surfaces a less-specific "invalid port" error.
  if (colonIdx !== -1 && decoded.indexOf(':', colonIdx + 1) !== -1) {
    throw new Error(
      `createDidWebIdentity: domain "${sanitizeForError(input)}" decodes to a value with multiple ":" delimiters`
    );
  }
  const hostPart = colonIdx === -1 ? decoded : decoded.slice(0, colonIdx);
  const portPart = colonIdx === -1 ? null : decoded.slice(colonIdx + 1);

  if (!isValidRegName(hostPart)) {
    throw new Error(
      `createDidWebIdentity: domain "${sanitizeForError(input)}" decodes to an invalid hostname`
    );
  }
  if (portPart !== null && !isValidPort(portPart)) {
    throw new Error(
      `createDidWebIdentity: domain "${sanitizeForError(input)}" decodes to an invalid port`
    );
  }

  return input;
}

/**
 * Validate a did:web path segment.
 *
 * Same defence-in-depth approach as {@link validateDidWebDomain}:
 * reject unencoded `:` and `/`, decode and reject traversal byte
 * sequences (`%2F`, `%00`, `..`), then enforce a structural character
 * class that matches the RFC 3986 `segment` grammar (the subset
 * actually used by DID method paths).
 */
function validateDidWebSegment(segment: string): string {
  if (segment.length === 0) {
    throw new Error(
      'createDidWebIdentity: path segments must be non-empty strings'
    );
  }
  if (segment.includes(':')) {
    throw new Error(
      `createDidWebIdentity: path segment "${sanitizeForError(segment)}" must not contain ":"; percent-encode if intentional`
    );
  }
  if (segment.includes('/')) {
    throw new Error(
      `createDidWebIdentity: path segment "${sanitizeForError(segment)}" must not contain "/"`
    );
  }

  let decoded: string;
  try {
    decoded = decodeURIComponent(segment);
  } catch {
    throw new Error(
      `createDidWebIdentity: path segment "${sanitizeForError(segment)}" contains an invalid percent-encoded byte sequence`
    );
  }

  if (decoded === '.' || decoded === '..') {
    throw new Error(
      `createDidWebIdentity: path segment "${sanitizeForError(segment)}" must not decode to a relative path component`
    );
  }
  if (
    decoded.includes('/') ||
    decoded.includes('\\') ||
    decoded.includes('\0')
  ) {
    throw new Error(
      `createDidWebIdentity: path segment "${sanitizeForError(segment)}" must not decode to a value containing "/", "\\", or NUL`
    );
  }

  // The W3C CCG did:web Method Specification (§3 DID Method Operations)
  // defines a did:web DID's path component as a method-specific
  // identifier, but does NOT normatively constrain its character set.
  // It therefore inherits whatever the broader URI grammar permits.
  //
  // This implementation adopts RFC 3986 §3.3 `pchar` as the segment
  // character class — minus the literal `:`, which is the did:web
  // path separator (callers must percent-encode it as `%3A` inside a
  // segment, which `pct-encoded` already permits).
  //
  // `pchar = unreserved / pct-encoded / sub-delims / ":" / "@"`
  //
  // The choice is implementation policy, not spec-mandated: any
  // downstream port may adopt a different (typically stricter) set
  // and still be conformant. Widening to the full pchar class
  // (vs the earlier `unreserved + pct-encoded` only) keeps this
  // factory capable of recreating any spec-conformant did:web DID a
  // different implementation might emit — e.g. `alice!bob`,
  // `O'Brien`, `c++`, `user@host`. A narrower port would reject those.
  if (
    !/^(?:[A-Za-z0-9\-._~!$&'()*+,;=@]|%[0-9A-Fa-f]{2})+$/.test(segment)
  ) {
    throw new Error(
      `createDidWebIdentity: path segment "${sanitizeForError(segment)}" contains characters disallowed by RFC 3986 pchar grammar`
    );
  }

  return segment;
}

/**
 * Validate a caller-supplied `kidFragment` against the RFC 3986
 * `fragment` grammar.
 *
 * Rejects the empty string, an embedded `#` (only one fragment
 * delimiter per URI), whitespace, control characters, and any byte
 * outside the documented grammar. Permits the full `pchar / "/" / "?"`
 * character class so callers can use the same fragments their DID
 * Documents declare (e.g. `keys-1`, `controller-2024`, `verification-method-1`).
 *
 * Unlike {@link validateDidWebDomain} and {@link validateDidWebSegment},
 * this validator deliberately does **not** percent-decode and
 * re-check the input. Decode-and-recheck guards against path-traversal
 * semantics (e.g. `%2F` becoming `/`), which only matter when the
 * value participates in URL path construction. A fragment is an
 * opaque verification-method identifier — its percent-encoded bytes
 * carry no path semantics, so RFC 3986 explicitly permits any
 * `pct-encoded` octet inside it. Adding decode-and-recheck here would
 * make the helper stricter than the spec.
 */
function validateDidWebKidFragment(fragment: string): string {
  if (fragment.length === 0) {
    throw new Error('createDidWebIdentity: kidFragment must not be empty');
  }
  if (!RFC3986_FRAGMENT_PATTERN.test(fragment)) {
    throw new Error(
      `createDidWebIdentity: kidFragment "${sanitizeForError(fragment)}" contains characters disallowed by RFC 3986 fragment grammar`
    );
  }
  return fragment;
}

/**
 * Sanitise caller-supplied input for inclusion in an error message.
 *
 * Identity-protocol error pipelines frequently flow into logs that
 * downstream operators read line-by-line. A caller able to splice
 * control bytes, NULs, ANSI escapes, or bidi-override characters
 * through a thrown error message can spoof log entries (CR/LF
 * splitting, bidi-rewritten attacker text — see CVE-2021-42574
 * "Trojan Source"), break structured-log parsers, or hijack a
 * terminal session.
 *
 * Two-stage defence:
 *
 *   1. Truncate to {@link ERROR_ECHO_MAX_LENGTH} **code points**
 *      (not UTF-16 code units) — slicing by code units can split a
 *      surrogate pair, producing invalid UTF-16 that downstream
 *      JSON loggers may double-encode or corrupt.
 *
 *   2. Hex-escape every character matched by
 *      {@link CONTROL_CHAR_PATTERN} — C0, C1, zero-width / direction
 *      marks, explicit bidi overrides, and bidi isolates.
 */
// Characters the sanitiser MUST hex-escape to defeat log spoofing
// and terminal hijacking:
//
//   - U+0000–U+001F : C0 controls (NUL log injection, CR/LF line
//     splitting, TAB column shifting, BEL terminal interaction)
//   - U+007F–U+009F : C1 controls (DEL, CSI 0x9B, etc.)
//   - U+200B–U+200F : ZWSP, ZWNJ, ZWJ, LRM, RLM (invisible / mis-
//     rendered text)
//   - U+202A–U+202E : LRE, RLE, PDF, LRO, RLO (Trojan-Source class
//     bidi overrides — CVE-2021-42574)
//   - U+2066–U+2069 : LRI, RLI, FSI, PDI (bidi isolates with the
//     same display-spoofing capability)
//
// Constructed from a string source so the regex literal in this file
// carries no unprintable bytes — both for readability and to satisfy
// `no-control-regex` without opt-out directives.
const CONTROL_CHAR_PATTERN = new RegExp(
  // eslint-disable-next-line no-control-regex
  '[\\u0000-\\u001F\\u007F-\\u009F\\u200B-\\u200F\\u202A-\\u202E\\u2066-\\u2069]',
  'g'
);

function sanitizeForError(input: string): string {
  // Truncate by code points, not UTF-16 code units. `String.prototype.slice`
  // cuts in the middle of surrogate pairs; `Array.from` iterates code
  // points so the result is always well-formed UTF-16.
  const codePoints = Array.from(input);
  const truncated =
    codePoints.length > ERROR_ECHO_MAX_LENGTH
      ? `${codePoints.slice(0, ERROR_ECHO_MAX_LENGTH - 3).join('')}...`
      : input;
  return truncated.replace(CONTROL_CHAR_PATTERN, (c) => {
    // Encode each code unit at the matched position. For BMP
    // controls this is just `\xHH`; for the higher bidi ranges we
    // emit `\uHHHH` to make the substitution unambiguous to a
    // downstream log parser.
    const code = c.charCodeAt(0);
    return code <= 0xff
      ? `\\x${code.toString(16).padStart(2, '0').toUpperCase()}`
      : `\\u${code.toString(16).padStart(4, '0').toUpperCase()}`;
  });
}

/**
 * RFC 952 / RFC 1123 hostname grammar: 1–253 chars total, dot-
 * separated labels of 1–63 chars each, letters/digits/hyphens, no
 * leading or trailing hyphen per label.
 */
function isValidRegName(hostname: string): boolean {
  if (hostname.length === 0 || hostname.length > 253) {
    return false;
  }
  const labels = hostname.split('.');
  for (const label of labels) {
    if (label.length === 0 || label.length > 63) {
      return false;
    }
    if (!/^[A-Za-z0-9-]+$/.test(label)) {
      return false;
    }
    if (label.startsWith('-') || label.endsWith('-')) {
      return false;
    }
  }
  return true;
}

/**
 * Validate a decoded did:web port component.
 *
 * RFC 3986 §3.2.3 defines the URI port grammar as `port = *DIGIT` —
 * no upper bound. We additionally bound to the IANA TCP/UDP port
 * range (0–65535) per RFC 6335 §6, since a did:web DID Document
 * served over HTTPS cannot reach a port outside that range anyway.
 * The lower bound (0) is reserved by IANA but syntactically valid
 * and emitted by some test vectors; we accept it rather than
 * over-stricting and forcing a special case downstream.
 *
 * @see RFC 3986 §3.2.3 (syntactic grammar)
 * @see RFC 6335 §6 (port-range semantics)
 */
function isValidPort(port: string): boolean {
  if (port.length === 0 || port.length > 5) {
    return false;
  }
  if (!/^[0-9]+$/.test(port)) {
    return false;
  }
  const n = Number(port);
  return n >= 0 && n <= 65535;
}

/**
 * Detach the produced Identity's `metadata` from the caller's input
 * object so subsequent mutations on either side do not leak across.
 *
 * Uses `structuredClone` to clone nested values too: shallow cloning
 * (`{ ...m }`) still shares references for nested objects, which would
 * defeat the point for callers attaching structured metadata.
 *
 * Wraps `structuredClone` failures (functions, DOM nodes, host-bound
 * objects) in a helper-prefixed error so callers see a consistent
 * construction-throws message rather than a raw `DataCloneError` /
 * `DOMException` from the platform.
 */
function cloneMetadata(
  metadata: Record<string, unknown> | undefined
): Record<string, unknown> | undefined {
  if (metadata === undefined) {
    return undefined;
  }
  try {
    return structuredClone(metadata);
  } catch (cause) {
    throw new Error(
      'identity-factory: metadata contains values that cannot be structurally cloned (functions, DOM nodes, host-bound objects)',
      { cause }
    );
  }
}

/**
 * Validate and normalise the optional `path` argument.
 *
 * TypeScript narrows `args.path` to `readonly string[] | undefined` for
 * strict callers, but plain-JavaScript consumers (and accidental
 * `as unknown as` casts) can still pass non-array values. Surface that
 * as a helper-prefixed construction error rather than letting `.map`
 * throw a cryptic `TypeError`.
 */
function validatePath(path: readonly string[] | undefined): string[] {
  if (path === undefined) {
    return [];
  }
  if (!Array.isArray(path)) {
    throw new Error(
      'createDidWebIdentity: args.path must be an array of strings when supplied'
    );
  }
  return path.map(validateDidWebSegment);
}

function nowIso(clock?: ClockProvider): string {
  const ms = clock ? clock.now() : Date.now();
  return new Date(ms).toISOString();
}
