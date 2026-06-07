import type { FetchProvider } from '../providers/base.js';
import type { DIDResolver } from './vc-verifier.js';

export type DIDResolverFactory = (fetchProvider: FetchProvider) => DIDResolver;
export type DIDResolverRegistryEntry = DIDResolver | DIDResolverFactory;
export type DIDResolverRegistry = Record<string, DIDResolverRegistryEntry>;

export function buildDidResolverRegistry(
  entries: DIDResolverRegistry | undefined,
  fetchProvider: FetchProvider | undefined,
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
        resolvers[method] = entry(fetchProvider);
      }
      continue;
    }
    resolvers[method] = entry;
  }

  return resolvers;
}
