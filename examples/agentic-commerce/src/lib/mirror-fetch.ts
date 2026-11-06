/**
 * DemoFetchProvider — the merchant's outbound HTTP, with two demo affordances
 * layered on the shipped RuntimeFetchProvider:
 *
 *  1. did:web is HTTPS by specification. For rehearsal the Responsible Party's
 *     hub runs on http://localhost, so `https://localhost[:port]/...` (and
 *     127.0.0.1) is rewritten to `http://` when ALLOW_INSECURE_LOCALHOST is on.
 *     Nothing else is ever downgraded.
 *
 *  2. A mirror map: when the network is down (or OFFLINE=1), a URL in the map
 *     is served from its mirror instead — e.g. the RP's public did.json from
 *     the hub's own copy. The console shows where each document came from, so
 *     the audience always knows whether they are looking at the internet or
 *     the laptop. Signatures are verified either way; the mirror only changes
 *     WHERE bytes came from, never whether they are trusted.
 */
import { RuntimeFetchProvider } from '@kya-os/mcp';

export interface DemoFetchProviderOptions {
  allowInsecureLocalhost?: boolean;
  /** original URL → mirror URL */
  mirrors?: Record<string, string>;
  offline?: boolean;
}

export type ResolvedFrom = 'network' | 'mirror';

export class DemoFetchProvider extends RuntimeFetchProvider {
  private readonly allowInsecureLocalhost: boolean;
  private readonly mirrors: Record<string, string>;
  private readonly offline: boolean;
  /** Last origin for each URL fetched through a mirror-capable path (for the console). */
  readonly resolvedFrom = new Map<string, ResolvedFrom>();

  constructor(options: DemoFetchProviderOptions = {}) {
    // The RP hub may be addressed as 127.0.0.1 in tests; the shipped SSRF guard
    // would refuse that IP literal. Loopback is exactly what we mean here.
    super({ allowPrivateNetworkHosts: true });
    this.allowInsecureLocalhost = options.allowInsecureLocalhost ?? true;
    this.mirrors = options.mirrors ?? {};
    this.offline = options.offline ?? false;
  }

  /** https://localhost → http://localhost, only for loopback hosts. */
  rewrite(url: string): string {
    if (!this.allowInsecureLocalhost) return url;
    try {
      const u = new URL(url);
      if (u.protocol === 'https:' && (u.hostname === 'localhost' || u.hostname === '127.0.0.1')) {
        u.protocol = 'http:';
        return u.toString();
      }
    } catch { /* not a URL — let the underlying fetch complain */ }
    return url;
  }

  override async fetch(url: string, options?: unknown): Promise<Response> {
    const mirror = this.mirrors[url];
    const primary = this.rewrite(url);

    if (mirror && this.offline) {
      const res = await super.fetch(this.rewrite(mirror), options);
      this.resolvedFrom.set(url, 'mirror');
      return res;
    }

    try {
      const res = await super.fetch(primary, options);
      if (res.ok || !mirror) {
        this.resolvedFrom.set(url, 'network');
        return res;
      }
    } catch (err) {
      if (!mirror) throw err;
    }
    const res = await super.fetch(this.rewrite(mirror!), options);
    this.resolvedFrom.set(url, 'mirror');
    return res;
  }
}
