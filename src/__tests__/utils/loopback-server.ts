/**
 * A real HTTP server on 127.0.0.1 for the tests of the readers that fetch a DID document or a
 * status list: started on a port the system picks, and closed with its open connections, so a
 * test that leaves a response unfinished does not keep the run alive.
 */
import type { Server } from 'node:http';

/** Start `server` on 127.0.0.1 and resolve with the port it listens on. */
export async function listenOnLoopback(server: Server): Promise<number> {
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  return (server.address() as { port: number }).port;
}

/** Close `server` and every connection still open to it. */
export async function closeLoopback(server: Server): Promise<void> {
  server.closeAllConnections();
  await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
}
