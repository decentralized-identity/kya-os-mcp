/**
 * A self-signed TLS certificate for one host name, made with nothing but `node:crypto`, so a test
 * can serve https on 127.0.0.1 and read it through the library's real `node:https` transport. The
 * certificate is an X.509 v3 one, its P-256 key signed with ECDSA over SHA-256, its subject and
 * issuer the host name, its one extension the host as a DNS subject alternative name, and valid
 * from an hour before it is made to an hour after.
 */
import { generateKeyPairSync, sign } from 'node:crypto';

/** The DER encoding of `parts` under `tag`, its length in the short or the long form. */
function der(tag: number, ...parts: Buffer[]): Buffer {
  const body = Buffer.concat(parts);
  const n = body.length;
  const length = n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : [0x82, n >> 8, n & 0xff];
  return Buffer.concat([Buffer.from([tag, ...length]), body]);
}

/** A DER SEQUENCE of `parts`. */
const sequence = (...parts: Buffer[]): Buffer => der(0x30, ...parts);

/** The DER encoding of the object identifier written `dotted`. */
function objectId(dotted: string): Buffer {
  const [first = 0, second = 0, ...rest] = dotted.split('.').map(Number);
  const bytes = [40 * first + second];
  for (const arc of rest) {
    const encoded = [arc & 0x7f];
    for (let high = arc >> 7; high > 0; high >>= 7) encoded.unshift((high & 0x7f) | 0x80);
    bytes.push(...encoded);
  }
  return der(0x06, Buffer.from(bytes));
}

/** `date` as a DER UTCTime, to the second. */
const utcTime = (date: Date): Buffer => der(0x17, Buffer.from(`${date.toISOString().replace(/[-:T]/g, '').slice(2, 14)}Z`));

/** An X.501 name with the one common name `commonName`. */
const nameOf = (commonName: string): Buffer => sequence(der(0x31, sequence(objectId('2.5.4.3'), der(0x0c, Buffer.from(commonName)))));

/** A certificate and its private key, both PEM, as `https.createServer` takes them. */
export interface SelfSignedTls {
  readonly cert: string;
  readonly key: string;
}

/** A self-signed certificate for `host`, and its key. */
export function selfSignedTls(host: string): SelfSignedTls {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const algorithm = sequence(objectId('1.2.840.10045.4.3.2'));
  const now = Date.now();
  const subjectAltName = sequence(objectId('2.5.29.17'), der(0x04, sequence(der(0x82, Buffer.from(host)))));
  const toBeSigned = sequence(
    der(0xa0, der(0x02, Buffer.from([2]))),
    der(0x02, Buffer.from([1])),
    algorithm,
    nameOf(host),
    sequence(utcTime(new Date(now - 3_600_000)), utcTime(new Date(now + 3_600_000))),
    nameOf(host),
    publicKey.export({ type: 'spki', format: 'der' }),
    der(0xa3, sequence(subjectAltName)),
  );
  const signature = sign('sha256', toBeSigned, privateKey);
  const certificate = sequence(toBeSigned, algorithm, der(0x03, Buffer.from([0]), signature));
  const lines = certificate.toString('base64').match(/.{1,64}/g) ?? [];
  return {
    cert: `-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n-----END CERTIFICATE-----\n`,
    key: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
  };
}
