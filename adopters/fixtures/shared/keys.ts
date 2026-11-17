/**
 * The parties of a fixture: each one Ed25519 key, named by a did:key or a did:web DID, with what the
 * library needs to sign as it, all made with the package's own public API.
 */
import {
  NodeCryptoProvider,
  base64ToBytes,
  base64urlEncodeFromBytes,
  buildDidWebDocument,
  didKeyFragment,
  generateDidKeyFromBase64,
  type DIDDocument,
} from '@kya-os/mcp';
import { ed25519SignerFromJwk, type ProofSigner } from '@kya-os/mcp/card';

/** The one crypto provider every fixture signs and verifies with. */
export const crypto = new NodeCryptoProvider();

/** A party: its DID, the id of its one key, that key as base64 raw bytes, and a Data Integrity signer for it. */
export interface Party {
  did: string;
  kid: string;
  /** The 32-byte Ed25519 public key, base64. */
  publicKey: string;
  /** The 32-byte Ed25519 seed, base64. */
  privateKey: string;
  /** Signs `eddsa-jcs-2022` proofs as `kid`, for status lists and Entity Card delegation hops. */
  signer: ProofSigner;
}

/** A new key, named `kid` under `did`. */
async function partyWithNewKey(name: (publicKey: string) => { did: string; kid: string }): Promise<Party> {
  const { publicKey, privateKey } = await crypto.generateKeyPair();
  const { did, kid } = name(publicKey);
  const signer = await ed25519SignerFromJwk({
    did,
    kid,
    privateJwk: {
      kty: 'OKP',
      crv: 'Ed25519',
      x: base64urlEncodeFromBytes(base64ToBytes(publicKey)),
      d: base64urlEncodeFromBytes(base64ToBytes(privateKey)),
    },
  });
  return { did, kid, publicKey, privateKey, signer };
}

/** A party known by the did:key of a new key. */
export function didKeyParty(): Promise<Party> {
  return partyWithNewKey((publicKey) => {
    const did = generateDidKeyFromBase64(publicKey);
    return { did, kid: `${did}#${didKeyFragment(did)}` };
  });
}

/** A party known by `did`, a did:web DID, whose document lists a new key as `#key-1`. */
export function didWebParty(did: string): Promise<Party> {
  return partyWithNewKey(() => ({ did, kid: `${did}#key-1` }));
}

/** The DID document a did:web party serves, as `buildDidWebDocument` writes it. */
export function didDocumentOf(party: Party): DIDDocument {
  return buildDidWebDocument({
    did: party.did,
    kid: party.kid,
    publicKey: party.publicKey,
    createdAt: new Date().toISOString(),
  });
}
