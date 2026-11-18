/**
 * Outbound Delegation Propagation Demo
 *
 * Demonstrates KYA-OS §8: how an MCP server forwards delegation context
 * to downstream services using HTTP headers, and how the downstream service
 * derives authorization from the delegation credential (§8.1).
 *
 * Run with: npx tsx examples/outbound-delegation/demo.ts
 */

import * as crypto from 'node:crypto';
import { decodeJwt, decodeProtectedHeader } from 'jose';
import {
  CryptoProvider,
  DelegationCredentialIssuer,
  DelegationCredentialVerifier,
  base64urlEncodeFromBytes,
  buildOutboundDelegationHeaders,
  completeVCJWT,
  createDidKeyResolver,
  createUnsignedVCJWT,
  generateDidKeyFromBase64,
  parseVCJWT,
  scopeSatisfies,
  type DelegationCredential,
  type DelegationRecord,
  type SessionContext,
  type VCSigningFunction,
} from '@kya-os/mcp';

// ---------------------------------------------------------------------------
// NodeCryptoProvider — Ed25519 operations using node:crypto
// ---------------------------------------------------------------------------

class NodeCryptoProvider extends CryptoProvider {
  async sign(data: Uint8Array, privateKeyBase64: string): Promise<Uint8Array> {
    const privateKey = Buffer.from(privateKeyBase64, 'base64');
    const keyBytes = privateKey.length === 64 ? privateKey.subarray(0, 32) : privateKey;

    const pkcs8 = Buffer.concat([
      Buffer.from('302e020100300506032b657004220420', 'hex'),
      keyBytes,
    ]);

    const keyObject = crypto.createPrivateKey({
      key: pkcs8,
      format: 'der',
      type: 'pkcs8',
    });

    const signature = crypto.sign(null, Buffer.from(data), keyObject);
    return new Uint8Array(signature);
  }

  async verify(
    data: Uint8Array,
    signature: Uint8Array,
    publicKeyBase64: string
  ): Promise<boolean> {
    try {
      const publicKey = Buffer.from(publicKeyBase64, 'base64');
      const spki = Buffer.concat([
        Buffer.from('302a300506032b6570032100', 'hex'),
        publicKey,
      ]);

      const keyObject = crypto.createPublicKey({
        key: spki,
        format: 'der',
        type: 'spki',
      });

      return crypto.verify(null, Buffer.from(data), keyObject, Buffer.from(signature));
    } catch {
      return false;
    }
  }

  async generateKeyPair(): Promise<{ privateKey: string; publicKey: string }> {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
      publicKeyEncoding: { type: 'spki', format: 'der' },
      privateKeyEncoding: { type: 'pkcs8', format: 'der' },
    });

    const rawPrivate = (privateKey as Buffer).subarray(16, 48);
    const rawPublic = (publicKey as Buffer).subarray(12, 44);

    return {
      privateKey: rawPrivate.toString('base64'),
      publicKey: rawPublic.toString('base64'),
    };
  }

  async hash(data: Uint8Array): Promise<string> {
    const hex = crypto.createHash('sha256').update(Buffer.from(data)).digest('hex');
    return `sha256:${hex}`;
  }

  async randomBytes(length: number): Promise<Uint8Array> {
    return new Uint8Array(crypto.randomBytes(length));
  }
}

// ---------------------------------------------------------------------------
// Main demo
// ---------------------------------------------------------------------------

async function main() {
  console.log('='.repeat(70));
  console.log('KYA-OS Outbound Delegation Propagation Demo');
  console.log('='.repeat(70));
  console.log();

  const cryptoProvider = new NodeCryptoProvider();

  // -------------------------------------------------------------------------
  // Step 1: Create two identities — Server A and Agent
  // -------------------------------------------------------------------------
  console.log('Step 1: Creating identities...');
  console.log('-'.repeat(70));

  const serverAKeys = await cryptoProvider.generateKeyPair();
  const serverADid = generateDidKeyFromBase64(serverAKeys.publicKey);
  const serverAKid = `${serverADid}#${serverADid.replace('did:key:', '')}`;
  console.log(`Server A DID: ${serverADid.slice(0, 30)}...`);

  const agentKeys = await cryptoProvider.generateKeyPair();
  const agentDid = generateDidKeyFromBase64(agentKeys.publicKey);
  console.log(`Agent DID:    ${agentDid.slice(0, 30)}...`);
  console.log();

  // -------------------------------------------------------------------------
  // Step 2: Issue a delegation from Server A to the Agent
  // -------------------------------------------------------------------------
  console.log('Step 2: Issuing delegation from Server A to Agent...');
  console.log('-'.repeat(70));

  const signingFunction: VCSigningFunction = async (canonicalVC, issuerDid, kid) => {
    const sig = await cryptoProvider.sign(
      new TextEncoder().encode(canonicalVC),
      serverAKeys.privateKey
    );
    return {
      type: 'Ed25519Signature2020',
      created: new Date().toISOString(),
      verificationMethod: kid,
      proofPurpose: 'assertionMethod',
      proofValue: Buffer.from(sig).toString('base64url'),
    };
  };

  const issuer = new DelegationCredentialIssuer(
    {
      getDid: () => serverADid,
      getKeyId: () => serverAKid,
      getPrivateKey: () => serverAKeys.privateKey,
    },
    signingFunction
  );

  const delegationVC = await issuer.createAndIssueDelegation({
    id: 'delegation-001',
    issuerDid: serverADid,
    subjectDid: agentDid,
    constraints: {
      scopes: ['tool:execute', 'resource:read'],
      notAfter: Math.floor(Date.now() / 1000) + 3600, // 1 hour
    },
  });

  const delegation: DelegationRecord = {
    id: delegationVC.credentialSubject.delegation.id,
    issuerDid: serverADid,
    subjectDid: agentDid,
    vcId: delegationVC.id || `urn:uuid:${delegationVC.credentialSubject.delegation.id}`,
    constraints: delegationVC.credentialSubject.delegation.constraints,
    signature: delegationVC.proof?.proofValue || '',
    status: 'active',
    createdAt: Date.now(),
  };

  // The same credential as a VC-JWT, the form KYA-OS-Delegation-Credential
  // carries (§8.1): Server A, its issuer, signs the JWT envelope.
  const vcWithoutProof = { ...delegationVC } as Record<string, unknown>;
  delete vcWithoutProof['proof'];
  const { signingInput } = createUnsignedVCJWT(vcWithoutProof, { keyId: serverAKid });
  const envelope = await cryptoProvider.sign(new TextEncoder().encode(signingInput), serverAKeys.privateKey);
  const credentialJwt = completeVCJWT(signingInput, base64urlEncodeFromBytes(envelope));

  console.log(`Delegation ID: ${delegation.id}`);
  console.log(`VC ID:         ${delegation.vcId}`);
  console.log(`Scopes:        ${delegation.constraints.scopes?.join(', ')}`);
  console.log(`VC-JWT:        ${credentialJwt.slice(0, 40)}...`);
  console.log();

  // -------------------------------------------------------------------------
  // Step 3: Simulate Server A receiving a tool call from the Agent
  // -------------------------------------------------------------------------
  console.log('Step 3: Simulating tool call from Agent to Server A...');
  console.log('-'.repeat(70));

  const session: SessionContext = {
    sessionId: `kyaos_${crypto.randomUUID()}`,
    audience: serverADid,
    nonce: crypto.randomUUID(),
    timestamp: Math.floor(Date.now() / 1000),
    createdAt: Date.now(),
    lastActivity: Date.now(),
    ttlMinutes: 30,
    identityState: 'authenticated',
    agentDid: agentDid,
    serverDid: serverADid,
    delegationRef: delegation.id,
    delegationChain: delegation.vcId,
    delegationScopes: delegation.constraints.scopes,
  };

  console.log(`Session ID: ${session.sessionId}`);
  console.log(`Agent is calling tool: "fetch_remote_data"`);
  console.log(`Server A needs to call downstream API to fulfill this request...`);
  console.log();

  // -------------------------------------------------------------------------
  // Step 4: Build outbound delegation headers
  // -------------------------------------------------------------------------
  console.log('Step 4: Building outbound delegation headers...');
  console.log('-'.repeat(70));

  const targetUrl = 'https://downstream-api.example.com/v1/data';

  const headers = await buildOutboundDelegationHeaders({
    session,
    delegation,
    credentialJwt,
    serverIdentity: {
      did: serverADid,
      kid: serverAKid,
      privateKey: serverAKeys.privateKey,
    },
    targetUrl,
  });

  console.log('Outbound Headers:');
  const sentCredential = headers['KYA-OS-Delegation-Credential'];
  console.log(`  KYA-OS-Delegation-Credential: ${sentCredential ? `${sentCredential.slice(0, 40)}...` : '(not sent)'}`);
  console.log(`  KYA-OS-Agent-DID:             ${headers['KYA-OS-Agent-DID'].slice(0, 40)}...`);
  console.log(`  KYA-OS-Delegation-Chain:      ${headers['KYA-OS-Delegation-Chain']} (advisory)`);
  console.log(`  KYA-OS-Session-Id:            ${headers['KYA-OS-Session-Id']}`);
  console.log(`  KYA-OS-Delegation-Proof:      ${headers['KYA-OS-Delegation-Proof'].slice(0, 40)}...`);
  console.log();

  // -------------------------------------------------------------------------
  // Step 5: Decode the KYA-OS-Delegation-Proof JWT
  // -------------------------------------------------------------------------
  console.log('Step 5: Decoding the KYA-OS-Delegation-Proof JWT...');
  console.log('-'.repeat(70));

  const jwt = headers['KYA-OS-Delegation-Proof'];
  const jwtHeader = decodeProtectedHeader(jwt);
  const jwtPayload = decodeJwt(jwt);

  console.log('JWT Header:');
  console.log(`  alg: ${jwtHeader.alg}`);
  console.log(`  kid: ${jwtHeader.kid?.slice(0, 40)}...`);
  console.log();

  console.log('JWT Payload:');
  console.log(`  iss:   ${(jwtPayload.iss as string).slice(0, 40)}... (Server A)`);
  console.log(`  sub:   ${(jwtPayload.sub as string).slice(0, 40)}... (Agent)`);
  console.log(`  aud:   ${jwtPayload.aud} (downstream service)`);
  console.log(`  iat:   ${jwtPayload.iat} (${new Date((jwtPayload.iat as number) * 1000).toISOString()})`);
  console.log(`  exp:   ${jwtPayload.exp} (${new Date((jwtPayload.exp as number) * 1000).toISOString()})`);
  console.log(`  jti:   ${jwtPayload.jti}`);
  console.log(`  scope: ${jwtPayload.scope}`);
  console.log();

  // -------------------------------------------------------------------------
  // Step 6: Server B derives authority from the delegation credential
  // -------------------------------------------------------------------------
  console.log('Step 6: Server B (downstream) derives authorization from the credential...');
  console.log('-'.repeat(70));

  // §8.1: granted scopes and the chain come from KYA-OS-Delegation-Credential.
  // The advisory KYA-OS-Delegation-Chain header is never read for the decision.
  const presented = headers['KYA-OS-Delegation-Credential'];
  if (presented === undefined) {
    throw new Error('No KYA-OS-Delegation-Credential header: Server B can authorize nothing');
  }
  const verifier = new DelegationCredentialVerifier({ didResolver: createDidKeyResolver() });
  const verified = await verifier.verifyDelegationJwt(presented);
  const vc = parseVCJWT(presented)?.payload.vc as unknown as DelegationCredential;
  const namesAgent = vc.credentialSubject.id === headers['KYA-OS-Agent-DID'];
  const requiredScope = 'tool:execute';
  const granted = scopeSatisfies(requiredScope, vc).satisfied;

  const checks: [string, boolean, string?][] = [
    ['Credential signature, expiry and status verify?', verified.valid, verified.reason],
    ['Credential subject is KYA-OS-Agent-DID?', namesAgent],
    [`Credential grants "${requiredScope}"?`, granted],
  ];
  checks.forEach(([label, ok, why], index) => {
    console.log(`  ${index + 1}. ${label.padEnd(47)} ${ok ? 'YES' : `NO${why ? ` (${why})` : ''}`}`);
  });
  console.log();

  console.log('Server B also checks the KYA-OS-Delegation-Proof JWT:');
  console.log(`  - its signature, under the key of iss (${(jwtPayload.iss as string).slice(0, 30)}...)`);
  console.log(`  - its timing: iat (${jwtPayload.iat}) is recent and exp (${jwtPayload.exp}) has not passed`);
  console.log(`  - its audience: aud (${jwtPayload.aud}) is Server B's hostname`);
  console.log(`  - its scope is "delegation:propagate"? ${jwtPayload.scope === 'delegation:propagate' ? 'YES' : 'NO'}`);
  console.log(`  - its sub is KYA-OS-Agent-DID?        ${jwtPayload.sub === headers['KYA-OS-Agent-DID'] ? 'YES' : 'NO'}`);
  console.log();

  const authorized = verified.valid && namesAgent && granted;
  console.log('='.repeat(70));
  console.log(authorized
    ? `Demo complete! Server B authorized "${requiredScope}" from the delegation credential.`
    : 'Demo failed: Server B could not authorize the call from the delegation credential.');
  console.log('='.repeat(70));
  if (!authorized) process.exitCode = 1;
}

main().catch((error: unknown) => {
  console.error(error);
  process.exitCode = 1;
});
