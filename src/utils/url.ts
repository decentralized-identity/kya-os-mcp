export function stripTrailingSlashes(value: string): string {
  let end = value.length;
  while (end > 0 && value.charCodeAt(end - 1) === 47) {
    end--;
  }
  return value.slice(0, end);
}

/**
 * Whether `url` includes credentials, a user name or a password before its host. The runtime's
 * `fetch` refuses such a URL; a request made of it otherwise would send them to the host it names.
 */
export function includesCredentials(url: URL): boolean {
  return url.username !== '' || url.password !== '';
}
