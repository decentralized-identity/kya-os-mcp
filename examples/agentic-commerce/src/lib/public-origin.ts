/** Public browser origins are configured, never inferred from proxy headers. */
export function publicOrigin(value: string): string {
  const url = new URL(value);
  if (url.username || url.password || url.pathname !== '/' || url.search || url.hash
    || !(url.protocol === 'https:' || isLoopbackHttp(url))) {
    throw new Error('Use an HTTPS origin, or HTTP on loopback for local development.');
  }
  return url.origin;
}

export function isLoopbackHttp(url: URL): boolean {
  return url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
}
