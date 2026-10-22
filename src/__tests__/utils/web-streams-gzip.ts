/**
 * GZIP through the Web Streams API (`CompressionStream` / `DecompressionStream`):
 * what a Workers / Deno / browser deployment injects in place of the package's
 * `node:zlib` status-list codec. Only used in tests, to exercise the injected
 * codec seams without loading `node:zlib`.
 */

async function pipe(bytes: Uint8Array, stream: CompressionStream | DecompressionStream): Promise<Uint8Array> {
  const piped = new Blob([new Uint8Array(bytes)]).stream().pipeThrough(stream);
  return new Uint8Array(await new Response(piped).arrayBuffer());
}

export const webStreamsGzip = (bytes: Uint8Array): Promise<Uint8Array> =>
  pipe(bytes, new CompressionStream('gzip'));

export const webStreamsGunzip = (bytes: Uint8Array): Promise<Uint8Array> =>
  pipe(bytes, new DecompressionStream('gzip'));
