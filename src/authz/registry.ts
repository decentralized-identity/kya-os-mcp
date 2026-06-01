import type { AuthorizationServerAdapter } from './adapter.js';
import type { AuthorizationRequirement, ToolProtection } from './requirement.js';

/**
 * Routes a tool's protection to exactly one {@link AuthorizationServerAdapter},
 * keyed by requirement type. Mirrors the provider-registry lifecycle (register
 * / get / list / resolve / seal) so the authorization seam composes the same
 * pluggable, sealed way the rest of the protocol does. In-memory and
 * dependency-free.
 */
export class AuthorizationServerRegistry {
  private readonly adapters = new Map<AuthorizationRequirement['type'], AuthorizationServerAdapter>();
  private sealed = false;

  /** Register an adapter for its requirement type. Throws on duplicate or when sealed. */
  register(adapter: AuthorizationServerAdapter): void {
    if (this.sealed) {
      throw new Error('AuthorizationServerRegistry is sealed; cannot register further adapters.');
    }
    if (this.adapters.has(adapter.type)) {
      throw new Error(`An adapter for type "${adapter.type}" is already registered.`);
    }
    this.adapters.set(adapter.type, adapter);
  }

  /** The adapter registered for a requirement type, if any. */
  get(type: AuthorizationRequirement['type']): AuthorizationServerAdapter | undefined {
    return this.adapters.get(type);
  }

  /** All registered adapters, in registration order. */
  list(): AuthorizationServerAdapter[] {
    return [...this.adapters.values()];
  }

  /**
   * Resolve the adapter that must run for a tool protection. Returns undefined
   * when the tool needs no authorization (`type: 'none'`) or no adapter is
   * registered for its requirement type.
   */
  resolve(protection: ToolProtection): AuthorizationServerAdapter | undefined {
    if (protection.requirement.type === 'none') return undefined;
    const adapter = this.adapters.get(protection.requirement.type);
    return adapter?.isRequired(protection) ? adapter : undefined;
  }

  /** Freeze the registry; subsequent registration throws. */
  seal(): void {
    this.sealed = true;
  }

  isSealed(): boolean {
    return this.sealed;
  }
}
