/**
 * The result a handler returns stays the handler's. The middleware attaches
 * its members (a proof, a proof error, the audit marker, its private members)
 * to a copy, and never writes to the object the handler returned or to its
 * `_meta`: a handler may return one object from every call, a module-level
 * constant or a cached result, and may freeze it. Each answer then carries
 * the members of its own call and no other. Over the real SDKs under both
 * response-proof profiles, and in process for the paths a client cannot
 * reach.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { z } from 'zod';
import { McpServer as McpServer2, createMcpHandler } from '@modelcontextprotocol/server';
import { Client as Client2, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { McpServer as McpServer1 } from '@modelcontextprotocol/sdk/server/mcp.js';
import { Client as Client1 } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { generateIdentity, withKyaOs } from '../with-kya-os-server.js';
import { toMcpToolCallback, type McpToolCallback } from '../mcp-tool-callback.js';
import type {
  KyaOsChallengeResult,
  KyaOsIdentityConfig,
  KyaOsMiddleware,
  KyaOsToolResult,
} from '../with-kya-os.js';
import {
  KYA_OS_PROOF_META_KEY,
  LEGACY_PROOF_META_KEY,
  RESPONSE_PROOF_PROFILE_ENVELOPE,
  type ResponseProofProfile,
} from '../../proof/generator.js';
import type { AuditTrailService } from '../../audit/service.js';
import { logger } from '../../logging/index.js';
import {
  connectTransport,
  createMiddleware,
  crypto,
  handshake,
  proofOf,
  verifyReceived,
} from './helpers/received-proof.js';

const ARGS = { item: 'x' };
const PROFILES = {
  body: { responseProofProfile: undefined, binds: 'content' },
  envelope: { responseProofProfile: RESPONSE_PROOF_PROFILE_ENVELOPE, binds: 'envelope' },
} as const satisfies Record<string, { responseProofProfile: ResponseProofProfile | undefined; binds: 'content' | 'envelope' }>;
type ProfileName = keyof typeof PROFILES;
const PROFILE_NAMES = Object.keys(PROFILES) as ProfileName[];

const AUDIT = 'org.kya-os/audit';
const UNPROVEN = 'Proof generation failed — response is unproven';
const AMBIGUOUS = 'Proof session is ambiguous (several live sessions, none threaded) — response is unproven';
const TERMINAL_AUDIT_FAILED = 'Required terminal audit delivery failed after tool completion';
const OUTCOME_AUDIT_FAILED = 'Required terminal audit delivery failed for authorization outcome';
const ERROR_AUDIT_FAILED = 'Required terminal audit delivery failed for an error response';
const RESOURCE_METADATA = 'https://shop.example/.well-known/oauth-protected-resource';
/** The proof members, under the namespaced key and (by default) mirrored under the legacy one. */
const PROOF = { [KYA_OS_PROOF_META_KEY]: expect.anything(), [LEGACY_PROOF_META_KEY]: expect.anything() };

/** `value`, and every object in it, frozen. */
function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const member of Object.values(value)) deepFreeze(member);
    Object.freeze(value);
  }
  return value;
}

/** The result every call of a tool returns, a frozen module-level constant. */
const REPORT: KyaOsToolResult = deepFreeze({
  content: [{ type: 'text', text: 'report r_1' }],
  structuredContent: { report: 'r_1' },
  _meta: { 'io.example/trace': 'trace-report' },
});

/** An error result every call returns, frozen. */
const FAILED: KyaOsToolResult = deepFreeze({
  content: [{ type: 'text', text: 'upstream unavailable' }],
  isError: true,
  _meta: { 'io.example/trace': 'trace-failed' },
});

/** A challenge application code proves with proveOutcome on every call, frozen. */
const CHALLENGE: KyaOsToolResult = deepFreeze({
  content: [{ type: 'text', text: 'Sign in to see this report.' }],
  structuredContent: { error: 'insufficient_scope', resource_metadata: RESOURCE_METADATA },
  _meta: { 'mcp/www_authenticate': [`Bearer resource_metadata="${RESOURCE_METADATA}"`] },
});

/** What a gate's formatChallenge hook returns on every call, frozen. */
const FORMATTED: KyaOsChallengeResult = deepFreeze({
  content: [{ type: 'text', text: 'Authorize this checkout first.' }],
  structuredContent: { error: 'insufficient_scope' },
  _meta: { 'io.example/trace': 'trace-gate' },
});

const AS_WRITTEN = {
  REPORT: structuredClone(REPORT),
  FAILED: structuredClone(FAILED),
  CHALLENGE: structuredClone(CHALLENGE),
  FORMATTED: structuredClone(FORMATTED),
};

/** The `_meta` a constant was written with. */
const metaOf = (name: keyof typeof AS_WRITTEN): Record<string, unknown> =>
  AS_WRITTEN[name]._meta as Record<string, unknown>;

/** Every constant is as it was written. */
function expectConstantsUnchanged(): void {
  expect({ REPORT, FAILED, CHALLENGE, FORMATTED }).toStrictEqual(AS_WRITTEN);
}

const CONSENT = {
  scopeId: 'cart:write',
  consentUrl: 'https://consent.example/authorize',
  formatChallenge: () => FORMATTED,
};

/** An audit sink that refuses the event types in `failing`, and accepts every other. */
function refusing(failing: () => readonly string[]): Pick<AuditTrailService, 'record'>['record'] {
  return async (event) => {
    if (failing().includes(event.eventType)) throw new Error('audit unavailable');
    return { status: 'pending', event: event as never };
  };
}

/**
 * The paths a result can take over the wire. `proved`: one session, the
 * proof made at send. `unproven`: no session, so the result goes out audited
 * and as the handler returned it. `proofError`: two live sessions and none
 * threaded, so the wrapper refuses to pick one and says the result is
 * unproven. `auditDegraded`: no session, and the audit trail refuses the
 * events each result's terminal record depends on, so each says its audit
 * failed.
 */
const PATHS = {
  proved: { autoSession: true, sessions: 0, failing: [] },
  unproven: { autoSession: false, sessions: 0, failing: [] },
  proofError: { autoSession: false, sessions: 2, failing: [] },
  auditDegraded: {
    autoSession: false,
    sessions: 0,
    failing: ['proof.rejected', 'tool.call.failed', 'tool.call.challenged'],
  },
} as const;
type PathName = keyof typeof PATHS;
const PATH_NAMES = Object.keys(PATHS) as PathName[];

/** Each tool, and the frozen constant it returns on every call. */
const TOOLS = {
  report: 'REPORT',
  failed: 'FAILED',
  challenge: 'CHALLENGE',
  gate_challenge: 'FORMATTED',
} as const satisfies Record<string, keyof typeof AS_WRITTEN>;
type ToolName = keyof typeof TOOLS;
const TOOL_NAMES = Object.keys(TOOLS) as ToolName[];

/** The tools, each returning one of the frozen constants on every call. */
async function setUp(
  kyaos: KyaOsMiddleware,
  path: PathName,
  register: (name: ToolName, callback: McpToolCallback<typeof ARGS>) => void,
): Promise<void> {
  register('report', toMcpToolCallback(kyaos.wrapWithProof('report', async () => REPORT)));
  register('failed', toMcpToolCallback(kyaos.wrapWithProof('failed', async () => FAILED)));
  register('challenge', toMcpToolCallback(async (args) => kyaos.proveOutcome!({
    toolName: 'challenge', args, outcome: 'needs_authorization', reason: 'insufficient_scope', result: CHALLENGE,
  })));
  register('gate_challenge', toMcpToolCallback(kyaos.wrapWithDelegation(
    'gate_challenge',
    CONSENT,
    async () => ({ content: [{ type: 'text', text: 'must not run' }] }),
  )));
  for (let session = 0; session < PATHS[path].sessions; session += 1) await handshake(kyaos);
}

const serverOptions = (identity: KyaOsIdentityConfig, profile: ProfileName, path: PathName) => ({
  crypto,
  identity,
  ...(PROFILES[profile].responseProofProfile === undefined
    ? {}
    : { responseProofProfile: PROFILES[profile].responseProofProfile }),
  handshakeExposure: 'none' as const,
  autoSession: PATHS[path].autoSession,
  audit: { record: refusing(() => PATHS[path].failing) },
});

/** JSON-RPC messages in a Streamable HTTP response body, JSON or SSE. */
function messagesIn(body: string): Array<{ id?: unknown; result?: Record<string, unknown>; error?: unknown }> {
  const text = body.trim();
  if (text.startsWith('{') || text.startsWith('[')) return [JSON.parse(text)].flat();
  return text
    .split('\n')
    .filter((line) => line.startsWith('data:'))
    .map((line) => JSON.parse(line.slice(5).trim()));
}

/** A tools/call answer as it crossed the wire. */
interface Answer {
  result?: Record<string, unknown>;
  error?: { code: number; message: string };
}

interface Wire {
  call(tool: ToolName): Promise<Answer>;
  close(): Promise<void>;
}

/** An SDK 2 server behind withKyaOs over Streamable HTTP in process, its client pinned to `era`. */
async function sdk2(
  era: '2025-11-25' | '2026-07-28',
  identity: KyaOsIdentityConfig,
  profile: ProfileName,
  path: PathName,
): Promise<Wire> {
  const handler = createMcpHandler(async () => {
    const server = new McpServer2({ name: 'handler-result', version: '1.0.0' });
    const kyaos = await withKyaOs(server, serverOptions(identity, profile, path));
    await setUp(kyaos, path, (name, callback) => server.registerTool(name, { inputSchema: { item: z.string() } }, callback));
    return server;
  }, { legacy: 'stateless' });
  const received = new Map<unknown, Answer>();
  const transport = new StreamableHTTPClientTransport(new URL('http://kya-os.test/mcp'), {
    fetch: async (url, init) => {
      const response = await handler.fetch(new Request(url, init));
      const sent = typeof init?.body === 'string' ? JSON.parse(init.body) : undefined;
      if (sent?.method === 'tools/call') {
        const answer = messagesIn(await response.clone().text()).find((message) => message.id === sent.id);
        if (answer !== undefined) received.set(sent.id, answer as Answer);
      }
      return response;
    },
  });
  const client = new Client2(
    { name: 'handler-result-client', version: '1.0.0' },
    era === '2026-07-28' ? { versionNegotiation: { mode: { pin: era } } } : undefined,
  );
  await client.connect(transport);
  expect(client.getNegotiatedProtocolVersion()).toBe(era);
  return {
    async call(tool) {
      const before = new Set(received.keys());
      await client.callTool({ name: tool, arguments: ARGS }).catch(() => undefined);
      const id = [...received.keys()].find((key) => !before.has(key));
      return received.get(id)!;
    },
    async close() {
      await client.close();
      await handler.close();
    },
  };
}

/** An SDK 1 server behind withKyaOs and its client, linked in memory; the wire is JSON. */
async function sdk1(identity: KyaOsIdentityConfig, profile: ProfileName, path: PathName): Promise<Wire> {
  const server = new McpServer1({ name: 'handler-result', version: '1.0.0' });
  const kyaos = await withKyaOs(server, serverOptions(identity, profile, path));
  await setUp(kyaos, path, (name, callback) => server.registerTool(name, { inputSchema: { item: z.string() } }, callback));
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const received: Answer[] = [];
  const forward = serverTransport.send.bind(serverTransport);
  serverTransport.send = async (message, sendOptions) => {
    const wire = JSON.parse(JSON.stringify(message));
    if (wire.result !== undefined || wire.error !== undefined) received.push(wire);
    return forward(wire, sendOptions);
  };
  await server.connect(serverTransport);
  const client = new Client1({ name: 'handler-result-client', version: '1.0.0' });
  await client.connect(clientTransport);
  return {
    async call(tool) {
      await client.callTool({ name: tool, arguments: ARGS }).catch(() => undefined);
      return received.at(-1)!;
    },
    async close() {
      await client.close();
      await server.close();
    },
  };
}

/** The `_meta` and `isError` the client receives from `tool` on `path`, and the outcome its proof records. */
function expectedAnswer(tool: ToolName, path: PathName): { _meta: Record<string, unknown>; isError?: true; outcome?: string } {
  const own = metaOf(TOOLS[tool]);
  const degraded = (reason: string) => ({ status: 'degraded', reason });
  if (tool === 'report') {
    return {
      proved: { _meta: { ...own, ...PROOF } },
      unproven: { _meta: { ...own } },
      proofError: { _meta: { ...own, proofError: AMBIGUOUS } },
      auditDegraded: { _meta: { ...own, [AUDIT]: degraded(TERMINAL_AUDIT_FAILED) }, isError: true as const },
    }[path];
  }
  if (tool === 'failed') {
    // An error result is never proved: its terminal audit is all there is to it.
    return path === 'auditDegraded'
      ? { _meta: { ...own, [AUDIT]: degraded(ERROR_AUDIT_FAILED) }, isError: true }
      : { _meta: { ...own }, isError: true };
  }
  const marker = { terminal: true, outcome: 'needs_authorization' };
  if (path === 'proved') return { _meta: { ...own, [AUDIT]: marker, ...PROOF }, outcome: 'needs_authorization' };
  if (path === 'auditDegraded') return { _meta: { ...own, [AUDIT]: { ...marker, ...degraded(OUTCOME_AUDIT_FAILED) } } };
  // An outcome without a session it may use goes out audited and unproven.
  return { _meta: { ...own, [AUDIT]: marker } };
}

const RUNS = [
  ['SDK 2', '2026-07-28'],
  ['SDK 2', '2025-11-25'],
  ['SDK 1', '2025-11-25'],
] as const;

describe.each(PROFILE_NAMES.flatMap((profile) => RUNS.map(([sdk, era]) => [profile, sdk, era] as const)))(
  'a frozen result returned from every call, %s profile, on %s at MCP %s',
  (profile, sdk, era) => {
    let error: ReturnType<typeof vi.spyOn>;
    beforeEach(() => {
      // A refused audit event is logged.
      error = vi.spyOn(logger, 'error').mockImplementation(() => {});
    });
    afterEach(() => error.mockRestore());

    it.each(PATH_NAMES.flatMap((path) => TOOL_NAMES.map((tool) => [path, tool] as const)))(
      '%s path, %s: the constant is unchanged and each answer carries its own members only',
      async (path, tool) => {
        const identity = await generateIdentity(crypto);
        const wire = sdk === 'SDK 2' ? await sdk2(era, identity, profile, path) : await sdk1(identity, profile, path);
        const expected = expectedAnswer(tool, path);
        const constant = AS_WRITTEN[TOOLS[tool]];
        // SDK 2 names the server in every result's `_meta` on the 2026-07-28 revision.
        const sdkMeta = sdk === 'SDK 2' && era === '2026-07-28'
          ? { 'io.modelcontextprotocol/serverInfo': { name: 'handler-result', version: '1.0.0' } }
          : {};

        try {
          for (const call of [1, 2]) {
            const answer = await wire.call(tool);

            expect(answer.error, `call ${call}`).toBeUndefined();
            expectConstantsUnchanged();
            const received = answer.result!;
            expect(received._meta, `call ${call}`).toStrictEqual({ ...expected._meta, ...sdkMeta });
            expect(received.isError, `call ${call}`).toBe(expected.isError);
            expect(received.content).toStrictEqual(constant.content);
            expect(received.structuredContent).toStrictEqual(constant.structuredContent);
            if (KYA_OS_PROOF_META_KEY in expected._meta) {
              expect(proofOf(received)?.meta.outcome).toBe(expected.outcome);
              expect(await verifyReceived(received, {
                signer: identity.did, toolName: tool, params: ARGS, binds: PROFILES[profile].binds,
              })).toMatchObject({ valid: true });
            }
          }
        } finally {
          await wire.close();
        }
      },
    );
  },
);

describe.each(PROFILE_NAMES)('one result returned from every call, in process (%s profile)', (profile) => {
  const { responseProofProfile, binds } = PROFILES[profile];
  const config = responseProofProfile === undefined ? {} : { responseProofProfile };
  let error: ReturnType<typeof vi.spyOn>;
  beforeEach(() => {
    error = vi.spyOn(logger, 'error').mockImplementation(() => {});
  });
  afterEach(() => error.mockRestore());

  it.each([
    ['delivered', [], { proofError: UNPROVEN }, undefined],
    ['refused', ['proof.rejected'], {
      proofError: UNPROVEN,
      [AUDIT]: { status: 'degraded', reason: 'Required proof-failure audit delivery failed after tool completion' },
    }, true],
  ] as const)(
    'says the result is unproven when its arguments cannot be hashed, the audit of that %s',
    async (_name, failing, members, isError) => {
      const kyaos = await createMiddleware({ ...config, audit: { record: refusing(() => failing) } });
      const sessionId = await handshake(kyaos);
      const wire = await connectTransport(kyaos);
      const report = kyaos.wrapWithProof('report', async () => REPORT);

      for (const call of [1, 2]) {
        // Arguments passed in process need not be JSON; a BigInt has no canonical form to sign.
        const result = await report({ amount: BigInt(call) }, sessionId);
        expectConstantsUnchanged();
        const received = await wire.send(result, { toolName: 'report', args: ARGS });

        expect(received._meta, `call ${call}`).toStrictEqual({ ...metaOf('REPORT'), ...members });
        expect(received.isError, `call ${call}`).toBe(isError);
      }
    },
  );

  it.each([
    ['delivered', [], {}, undefined],
    ['refused', ['tool.call.completed'], { [AUDIT]: { status: 'degraded', reason: TERMINAL_AUDIT_FAILED } }, true],
  ] as const)(
    'sends the result unproven when its threaded session is gone, its terminal audit %s',
    async (_name, failing, members, isError) => {
      const kyaos = await createMiddleware({ ...config, audit: { record: refusing(() => failing) } });
      const wire = await connectTransport(kyaos);
      const report = kyaos.wrapWithProof('report', async () => REPORT);

      for (const call of [1, 2]) {
        const received = await wire.send(await report(ARGS, 'kyaos_gone'), { toolName: 'report', args: ARGS });
        expectConstantsUnchanged();

        expect(received._meta, `call ${call}`).toStrictEqual({ ...metaOf('REPORT'), ...members });
        expect(received.isError, `call ${call}`).toBe(isError);
      }
    },
  );

  it('keeps no member of an earlier call on a shared result that is not frozen', async () => {
    let failing: string[] = ['tool.call.completed'];
    const kyaos = await createMiddleware({ ...config, audit: { record: refusing(() => failing) } });
    const sessionId = await handshake(kyaos);
    const wire = await connectTransport(kyaos);
    const shared: KyaOsToolResult = { content: [{ type: 'text', text: 'cached' }], _meta: { 'io.example/trace': 't' } };
    const asWritten = structuredClone(shared);
    const report = kyaos.wrapWithProof('report', async () => shared);

    // The first call names a session that is gone, and its terminal audit
    // is refused: its answer is an error whose audit failed...
    const first = await wire.send(await report(ARGS, 'kyaos_gone'), { toolName: 'report', args: ARGS });
    expect(first.isError).toBe(true);
    expect(first._meta).toStrictEqual({
      'io.example/trace': 't',
      [AUDIT]: { status: 'degraded', reason: TERMINAL_AUDIT_FAILED },
    });
    expect(shared).toStrictEqual(asWritten);

    // ...and the second, in a live session and audited, is proved: nothing
    // of the first is on it.
    failing = [];
    const second = await wire.send(await report(ARGS, sessionId), { toolName: 'report', args: ARGS });
    expect(shared).toStrictEqual(asWritten);
    expect(second.isError).toBeUndefined();
    expect(second._meta).toStrictEqual({ 'io.example/trace': 't', ...PROOF });
    expect((await verifyReceived(second, {
      signer: kyaos.identity.did, toolName: 'report', params: ARGS, binds,
    })).valid).toBe(true);
  });

  it('passes a gate outcome through a wrapWithProof around the gate as that outcome', async () => {
    const kyaos = await createMiddleware(config);
    const sessionId = await handshake(kyaos);
    const wire = await connectTransport(kyaos);
    const gated = kyaos.wrapWithProof('checkout', kyaos.wrapWithDelegation(
      'checkout',
      CONSENT,
      async () => ({ content: [{ type: 'text', text: 'must not run' }] }),
    ));

    for (const call of [1, 2]) {
      const received = await wire.send(await gated(ARGS, sessionId), { toolName: 'checkout', args: ARGS });
      expectConstantsUnchanged();

      // The challenge's own outcome proof, not one recording the call as allowed.
      expect(received._meta, `call ${call}`).toStrictEqual({
        ...metaOf('FORMATTED'),
        [AUDIT]: { terminal: true, outcome: 'needs_authorization' },
        ...PROOF,
      });
      expect(proofOf(received)?.meta.outcome).toBe('needs_authorization');
      expect((await verifyReceived(received, {
        signer: kyaos.identity.did, toolName: 'checkout', params: ARGS, binds,
      })).valid).toBe(true);
    }
  });

  describe('proveOutcome', () => {
    const prove = (kyaos: KyaOsMiddleware, args: Record<string, unknown>, sessionId: string) => kyaos.proveOutcome!({
      toolName: 'challenge', args, outcome: 'needs_authorization', reason: 'insufficient_scope', result: CHALLENGE, sessionId,
    });
    const marker = { terminal: true, outcome: 'needs_authorization' };

    it('says the outcome is unproven when its arguments cannot be hashed', async () => {
      const kyaos = await createMiddleware(config);
      const sessionId = await handshake(kyaos);
      const wire = await connectTransport(kyaos);

      for (const call of [1, 2]) {
        const result = await prove(kyaos, { amount: BigInt(call) }, sessionId);
        expectConstantsUnchanged();
        const received = await wire.send(result, { toolName: 'challenge', args: ARGS });

        expect(received._meta, `call ${call}`).toStrictEqual({ ...metaOf('CHALLENGE'), [AUDIT]: marker, proofError: UNPROVEN });
        expect(received.isError).toBeUndefined();
      }
    });

    it('says the outcome is unproven when its proof fails at send', async () => {
      const kyaos = await createMiddleware(config);
      const sessionId = await handshake(kyaos);
      const wire = await connectTransport(kyaos);
      const generate = vi.spyOn(kyaos.proofGenerator, 'generateProof').mockRejectedValue(new Error('signer offline'));

      try {
        for (const call of [1, 2]) {
          const received = await wire.send(await prove(kyaos, ARGS, sessionId), { toolName: 'challenge', args: ARGS });
          expectConstantsUnchanged();

          expect(received._meta, `call ${call}`).toStrictEqual({ ...metaOf('CHALLENGE'), [AUDIT]: marker, proofError: UNPROVEN });
        }
      } finally {
        generate.mockRestore();
      }
    });

    it('marks the outcome an error whose audit failed, on a copy, when its proof audit is refused', async () => {
      const kyaos = await createMiddleware({ ...config, audit: { record: refusing(() => ['proof.generated']) } });
      const sessionId = await handshake(kyaos);
      const wire = await connectTransport(kyaos);

      for (const call of [1, 2]) {
        const received = await wire.send(await prove(kyaos, ARGS, sessionId), { toolName: 'challenge', args: ARGS });
        expectConstantsUnchanged();

        // The envelope profile covers isError, so the proof is dropped there; the body profile keeps it.
        expect(received._meta, `call ${call}`).toStrictEqual({
          ...metaOf('CHALLENGE'),
          [AUDIT]: { ...marker, status: 'degraded', reason: 'Required proof audit delivery failed for authorization outcome' },
          ...(profile === 'body' ? PROOF : {}),
        });
        expect(received.isError).toBe(true);
      }
    });
  });
});
