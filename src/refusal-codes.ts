/**
 * Refusal codes: why a verifier refused, as a stable value code can branch on.
 *
 * Every refusal the library returns, of a delegation credential, a delegation chain, an Entity Card,
 * the delegation a request carries or a credential's status, carries one of these codes beside its
 * `reason`, with `transient`. A reason is text for people, and its wording may change from one
 * release to the next; a code does not, so a caller branches on the code and shows the reason.
 * The names are those of `KYA_OS_ERROR_CODES` where the meaning is the same, and new names only
 * where none is. A code is not part of any wire format: what a client receives is unchanged.
 *
 * A transient code says that the verifier could not decide, because something it depends on failed:
 * a deadline passed, a host could not be reached or failed, a status list could not be read, or a
 * dependency the host supplies threw. The same request may succeed later. Every other code is a
 * verdict, about the credential, its chain or the verifier's own configuration, which asking again
 * does not change. Whether a code is transient is fixed by the code ({@link isTransientRefusal}).
 */

/** Every refusal code, each the string it names. */
export const REFUSAL_CODES = Object.freeze({
  /**
   * The credential, or a value that stands for one, is not a well-formed delegation credential: it
   * fails the schema, its issuer is not a URL, its delegation names no issuer or subject or states no
   * status the verifier knows, its subject carries other members, it has no proof, a VC-JWT does not
   * parse, has claims that are not well formed or names another issuer than its `iss`, a time it
   * states is not a date, or it is not plain data, nests too deep or holds a value that cannot be
   * encoded. Also a status entry no
   * checker of the verifier reads: one that states another `statusPurpose` than the checker's, a
   * `statusSize` other than 1, an index that is not a non-negative decimal string, or an index past
   * the end of its status list. To `DelegationGraphManager`, also a status entry a delegation may
   * not be registered with: one not allocated to it, or one another delegation is registered with;
   * and to `StatusList2021Manager.updateStatus`, an entry of a list the manager does not issue.
   */
  delegation_malformed: 'delegation_malformed',
  /** The credential, a VC-JWT's `exp`, or a credential of the chain is past its expiry, or its delegation's `status` is `expired`. */
  delegation_expired: 'delegation_expired',
  /** The credential, a VC-JWT's `nbf`, or a credential of the chain is not yet valid. */
  delegation_not_yet_valid: 'delegation_not_yet_valid',
  /**
   * The credential, a credential of its chain, or an Entity Card is revoked: its status bit is set,
   * the revocation checker answered that it is, or its delegation's `status` is `revoked`.
   */
  delegation_revoked: 'delegation_revoked',
  /**
   * The verifier the host gives a chain walk for each credential refused one and gave no code, so the
   * library cannot say which rule it broke.
   */
  delegation_invalid: 'delegation_invalid',
  /**
   * A signature does not verify: the credential's proof or VC-JWT envelope does not hold under the
   * issuer's key, its `proofValue` is not one signature, its proof type is not one the verifier
   * checks, the signature verifier the host supplies refused it, or a hop's proof did not verify.
   */
  invalid_proof: 'invalid_proof',
  /**
   * The proof names a key the issuer's DID document does not list under `assertionMethod` as the
   * issuer's own, names no key and the document lists none to take, or states a `proofPurpose` other
   * than `assertionMethod`.
   */
  key_not_authorized: 'key_not_authorized',
  /**
   * The DID of a credential's issuer or of a status list's signer, or the document resolved for it,
   * is not valid: the DID or the key id is over its length limit, the DID is a did:key whose public
   * key does not decode, a did:web DID that names no URL or a DID of a method none of the delegation
   * gate's resolvers serves, the document is over a limit, its byte limit included, is not plain
   * JSON data or is not a document of that DID, or the key it lists for the proof is not a usable
   * Ed25519 public key.
   */
  did_invalid: 'did_invalid',
  /**
   * The reader's own rules refused the host of a DID document or a status list, on its URL or on a
   * redirect: a private or local host, a scheme the reader does not read, or a redirect it does not
   * follow. In local development, `development: true` admits private and local hosts. A name that
   * resolves to a private address is not refused with this code: the lookup decided that, so it is
   * refused as a name that does not resolve is, and the log says `host_refused`.
   */
  host_refused: 'host_refused',
  /** The chain's root is issued by a DID that `trustedRootIssuers` does not list, or that is not the `resourceOwner` the verifier pins. */
  untrusted_root: 'untrusted_root',
  /**
   * The credentials do not make one line of authority valid here: one does not descend from the one
   * before it, the chain repeats a credential, is empty, is incomplete or does not end at the
   * presented credential, a re-delegation is wider than its parent, a credential's audience does not
   * name this server or a re-delegation names none, the root does not name this resource, or the
   * chain is longer than `maxChainLength`.
   */
  chain_invalid: 'chain_invalid',
  /** The chain is valid, but does not grant the action the call exercises. */
  insufficient_scope: 'insufficient_scope',
  /**
   * No delegation was presented for a call that needs one: the request carries no chain and the
   * verifier has no by-reference resolver, or the resolver found none. The caller must obtain
   * authority, for example through a consent step, before it calls again.
   */
  needs_authorization: 'needs_authorization',
  /** The chain's leaf delegate is not the DID the request proof verified for. */
  holder_binding_failed: 'holder_binding_failed',
  /**
   * A status list was read, but it may not answer for the credential (SPEC.md §6.6): its issuer is
   * not the one keeper of the list's URL, or it names none, its proof does not verify under its
   * issuer's key, it states as its `id` another URL than the one it was read from, or its
   * `statusPurpose` does not include the entry's.
   */
  status_signer_untrusted: 'status_signer_untrusted',
  /**
   * An Entity Card's accountability, or one of its attestations, did not verify: the verifier the
   * host supplies for it answered no.
   */
  claim_unverified: 'claim_unverified',
  /**
   * The verifier is not set up to decide: it has no DID resolver or signature verifier, no status list
   * resolver for a credential that has a status, no `resolveDelegationChain` for a re-delegated
   * credential, no verifier for an Entity Card's accountability or attestations, or no status list
   * checker for an Entity Card that declares a revocation entry; an option such as `trustedRootIssuers`, `maxChainLength` or `dependencyTimeoutMs` has
   * a value it cannot use; or a checker that wraps a library checker passed on neither the context
   * nor the entry it was given.
   */
  configuration_error: 'configuration_error',
  /**
   * Transient. The DID document of a credential's issuer or of a status list's signer could not be
   * read: its host could not be reached or answered with something other than a document, the
   * resolver found none and gave no cause, or it threw.
   */
  did_unavailable: 'did_unavailable',
  /**
   * Transient. The credential's status could not be read: the status list could not be fetched or
   * decoded, or the status list resolver or revocation checker threw or gave an answer that is not
   * one it may give.
   */
  status_unavailable: 'status_unavailable',
  /**
   * Transient. A dependency did not answer within its deadline, `dependencyTimeoutMs`, 5 seconds by
   * default: a DID resolver, a status list read, resolver or checker, a chain resolver, a revocation
   * checker, or a verifier the host supplies.
   */
  deadline_exceeded: 'deadline_exceeded',
  /**
   * Transient. A dependency the host supplies, such as a signature verifier, a chain resolver or a hop
   * proof verifier, threw or gave an answer that is not one it may give, or the verification itself
   * faulted, so no verdict was reached.
   */
  runtime_error: 'runtime_error',
} as const);

/** A refusal code: one of {@link REFUSAL_CODES}. */
export type RefusalCode = (typeof REFUSAL_CODES)[keyof typeof REFUSAL_CODES];

/** The codes that say the verifier could not decide, rather than refused. */
const TRANSIENT: ReadonlySet<string> = new Set<RefusalCode>([
  'did_unavailable',
  'status_unavailable',
  'deadline_exceeded',
  'runtime_error',
]);

const CODES: ReadonlySet<string> = new Set<string>(Object.values(REFUSAL_CODES));

/** Whether `value` is one of the {@link REFUSAL_CODES}. */
export function isRefusalCode(value: unknown): value is RefusalCode {
  return typeof value === 'string' && CODES.has(value);
}

/**
 * Whether `code` is a transient refusal code: the verifier could not decide because something it
 * depends on failed, and the same request may succeed later. `false` for every other code, and for
 * a value that is not a refusal code.
 */
export function isTransientRefusal(code: unknown): boolean {
  return typeof code === 'string' && TRANSIENT.has(code);
}
