import type { FetchProvider } from '../providers/base.js';
import type { DIDResolver } from './vc-verifier.js';

/** What the owner of a registry tells each factory it calls. */
export interface DIDResolverFactoryContext {
  /**
   * The `dependencyTimeoutMs` the owner gives its own dependencies, for a resolver the factory
   * builds to wait as long, unless the factory's own options set another.
   */
  dependencyTimeoutMs?: number;
  /**
   * `true` when the owner runs with `development: true`, for a resolver the factory builds to admit
   * private and local hosts as the owner's own resolvers do, for example by passing it on as
   * `createDidWebResolver(fetchProvider, { development: context?.development })`.
   */
  development?: boolean;
}

export type DIDResolverFactory = (fetchProvider: FetchProvider, context?: DIDResolverFactoryContext) => DIDResolver;
export type DIDResolverRegistryEntry = DIDResolver | DIDResolverFactory;
export type DIDResolverRegistry = Record<string, DIDResolverRegistryEntry>;

export function buildDidResolverRegistry(
  entries: DIDResolverRegistry | undefined,
  fetchProvider: FetchProvider | undefined,
  context?: DIDResolverFactoryContext,
): Record<string, DIDResolver> {
  const resolvers: Record<string, DIDResolver> = {};
  if (!entries) {
    return resolvers;
  }

  for (const [method, entry] of Object.entries(entries)) {
    if (!/^[a-z0-9]+$/.test(method)) {
      continue;
    }
    if (typeof entry === 'function') {
      if (fetchProvider) {
        resolvers[method] = entry(fetchProvider, context);
      }
      continue;
    }
    resolvers[method] = entry;
  }

  return resolvers;
}
