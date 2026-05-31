import type { RiskAssessment } from './types.js';

export interface Invocation {
  toolName: string;
  namespace: string;
}

/**
 * Verbs denoting sensitive/destructive operations. Seeded from the intent of
 * the previously-dead `hasSensitiveScopes` helper, but applied to the resolved
 * ACT (tool verb) rather than the grant string.
 */
export const SENSITIVE_VERBS = [
  'delete',
  'drop',
  'destroy',
  'remove',
  'terminate',
  'transfer',
  'payment',
  'admin',
  'execute',
  'modify',
  'write',
  'rotate',
  'revoke',
] as const;

const READ_VERBS = ['read', 'get', 'list', 'describe', 'search', 'query'] as const;

export interface RiskClassifierOptions {
  /** Per-tool overrides keyed by exact toolName (a complete RiskAssessment wins outright). */
  hints?: Record<string, Partial<RiskAssessment>>;
}

/**
 * Classifies a tool invocation by reversibility, blast radius, and severity.
 *
 * HEURISTIC, best-effort — not a security boundary. It tokenizes the WHOLE tool
 * name (all path segments, split on . : / _ - and camelCase) and matches verbs as
 * WHOLE TOKENS (so `rewrite`/`underwrite` no longer match `write`, and `admin` in
 * `admin.users.read` is still seen). An unrecognized verb → `unknown`, which the
 * DefaultPolicyEngine fails closed (deny).
 *
 * KNOWN LIMITS, by design:
 * - It over-flags reads whose name contains a sensitive verb token (e.g.
 *   `list_payment_methods` → step-up). That is the safe direction.
 * - It does NOT understand that some reads are sensitive: `vault.getSecrets`
 *   classifies as a low-risk read and is allowed. Do NOT rely on the default
 *   classifier to gate read-sensitive tools — supply an explicit hint or a
 *   custom classifier for those.
 */
export class RiskClassifier {
  constructor(private readonly options: RiskClassifierOptions = {}) {}

  classify(invocation: Invocation): RiskAssessment {
    const hint = this.options.hints?.[invocation.toolName];
    if (hint?.reversibility && hint.blastRadius && hint.severity) {
      return {
        reversibility: hint.reversibility,
        blastRadius: hint.blastRadius,
        severity: hint.severity,
      };
    }

    const tokens = tokenize(invocation.toolName);
    const prod = isProd(invocation.namespace);

    let base: RiskAssessment;
    if (tokens.some((t) => (SENSITIVE_VERBS as readonly string[]).includes(t))) {
      base = {
        reversibility: 'irreversible',
        blastRadius: prod ? 'environment' : 'resource',
        severity: prod ? 'catastrophic' : 'high',
      };
    } else if (tokens.some((t) => (READ_VERBS as readonly string[]).includes(t))) {
      base = { reversibility: 'reversible', blastRadius: 'record', severity: 'low' };
    } else {
      base = { reversibility: 'unknown', blastRadius: 'unknown', severity: 'unknown' };
    }

    return { ...base, ...stripUndefined(hint) };
  }
}

/** Split a tool name (or namespace) into lowercase tokens across all path
 *  segments, separators (. : / _ - whitespace) and camelCase boundaries. */
function tokenize(name: string): string[] {
  return name
    .split(/[.:/_\-\s]+/)
    .flatMap((seg) => seg.replace(/([a-z0-9])([A-Z])/g, '$1 $2').split(/\s+/))
    .map((t) => t.toLowerCase())
    .filter(Boolean);
}

/** True only when the namespace contains a whole `prod`/`production` token
 *  (not a substring like `product`/`reproduce`). */
function isProd(namespace: string): boolean {
  const t = tokenize(namespace);
  return t.includes('prod') || t.includes('production');
}

function stripUndefined<T extends object>(o?: T): Partial<T> {
  if (!o) return {};
  const out: Partial<T> = {};
  for (const [k, v] of Object.entries(o)) {
    if (v !== undefined) (out as Record<string, unknown>)[k] = v;
  }
  return out;
}
