import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';

const mocks = vi.hoisted(() => ({ order: vi.fn(), commerce: vi.fn(), checkout: vi.fn() }));
vi.mock('../src/agent/agent.js', () => ({ runAgentOrder: mocks.order, browseCatalog: vi.fn() }));
vi.mock('../src/agent/commerce.js', () => ({ runAgentCommerce: mocks.commerce }));
vi.mock('../src/agent/store.js', () => ({ readAgentCheckout: mocks.checkout }));
vi.mock('../src/lib/wiring.js', async () => {
  const { NodeCryptoProvider } = await import('@kya-os/mcp');
  return { merchantOrigin: () => 'https://merchant.example', cryptoProvider: new NodeCryptoProvider(),
    flag: (name: string) => process.env[name] === '1' || process.env[name] === 'true' };
});
import { createGatewayServer } from '../src/agent/gateway.js';

const originalDescription = 'Place an order for a catalog product. If human consent is needed, returns a verified authorizationUrl to open and approve. After the human approves, retry within the approved product scope and per-order cap. The gateway attaches the new grant and a fresh holder proof. Returns an order receipt or a policy denial. This does not make a payment.';
const result = { result: { content: [{ type: 'text', text: JSON.stringify({ ok: true, orderId: 'ORD-1',
  order: { quantity: 2, name: 'Risotto', total: 'CHF 39.80' }, payment: { status: 'simulated', simulated: true } }) }] },
  elapsedMs: 1, agentDid: 'did:key:test-agent', presented: {} };
beforeEach(() => {
  vi.stubEnv('COMMERCE_PAYMENTS', undefined);
  mocks.order.mockReset().mockResolvedValue(result);
  mocks.commerce.mockReset().mockResolvedValue(result);
  mocks.checkout.mockReset().mockReturnValue(null);
});
afterEach(() => vi.unstubAllEnvs());

async function withGateway<T>(run: (client: Client) => Promise<T>): Promise<T> {
  const gateway = createGatewayServer({ merchantOrigin: 'https://merchant.example', audience: 'did:key:merchant' });
  const client = new Client({ name: 'workshop-connector-check', version: '1' });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  try {
    await gateway.connect(serverTransport);
    await client.connect(clientTransport);
    return await run(client);
  } finally { await client.close(); await gateway.close(); }
}

describe('workshop gateway payment opt-in', () => {
  it.each([undefined, '0', 'false', 'unexpected'])('preserves the original Claude tool contract when COMMERCE_PAYMENTS=%s', async value => {
    vi.stubEnv('COMMERCE_PAYMENTS', value);
    const tools = await withGateway(client => client.listTools());
    const order = tools.tools.find(tool => tool.name === 'place_order')!;
    expect(order.description).toBe(originalDescription);
    expect(order.inputSchema).toEqual({ type: 'object', properties: {
      product: { type: 'string', description: 'Catalog sku (e.g. "risotto") or a GS1 Digital Link URI' },
      quantity: { type: 'integer', minimum: 1, description: 'How many units (default 1)' },
    }, required: ['product'] });
    expect(mocks.order).not.toHaveBeenCalled();
    expect(mocks.commerce).not.toHaveBeenCalled();
    expect(mocks.checkout).not.toHaveBeenCalled();
  });

  it.each([
    { payment_protocol: 'x402' }, { payment_protocol: 'ucp' }, { payment_protocol: 'order-only' },
    { payment_method: 'x402' }, { payment_method: null }, { checkout_id: 'saved-checkout' },
  ])('refuses an unadvertised payment argument before wallet access or an unpaid order: %j', async args => {
    const response = await withGateway(client => client.callTool({ name: 'place_order', arguments: { product: 'risotto', quantity: 2, ...args } }));
    expect(response.isError).toBe(true);
    expect(JSON.stringify(response.content)).toContain('PAYMENTS_DISABLED');
    expect(mocks.checkout).not.toHaveBeenCalled();
    expect(mocks.order).not.toHaveBeenCalled();
    expect(mocks.commerce).not.toHaveBeenCalled();
  });

  it('keeps an ordinary order on the existing delegated order path', async () => {
    const response = await withGateway(client => client.callTool({ name: 'place_order', arguments: { product: 'risotto', quantity: 2 } }));
    expect(response.isError).toBeFalsy();
    expect(mocks.order).toHaveBeenCalledExactlyOnceWith({ product: 'risotto', quantity: 2, serverUrl: 'https://merchant.example/mcp', audience: 'did:key:merchant' });
    expect(mocks.commerce).not.toHaveBeenCalled();
    expect(mocks.checkout).not.toHaveBeenCalled();
    expect(JSON.stringify(response.content)).not.toContain('Payment:');
  });

  it.each(['1', 'true'])('exposes payment choices only with explicit opt-in %s', async value => {
    vi.stubEnv('COMMERCE_PAYMENTS', value);
    await withGateway(async client => {
      const order = (await client.listTools()).tools.find(tool => tool.name === 'place_order')!;
      expect(Object.keys(order.inputSchema.properties!)).toEqual(['product', 'quantity', 'payment_protocol', 'payment_method', 'checkout_id']);
      expect(order.description).toContain('Default order-only makes no payment');
      const paid = await client.callTool({ name: 'place_order', arguments: { product: 'risotto', quantity: 2, payment_protocol: 'x402' } });
      expect(paid.isError).toBeFalsy();
      expect(mocks.commerce).toHaveBeenCalledOnce();
      expect(mocks.order).not.toHaveBeenCalled();
    });
  });

  it('preserves the original consent response for an ordinary workshop order', async () => {
    const challenge = { error: 'needs_authorization', authorizationUrl: 'https://consent.example/consent?resume_token=approved-later', resumeToken: 'approved-later' };
    mocks.order.mockResolvedValue({ ...result, checkoutId: 'unused-payment-context',
      result: { content: [{ type: 'text', text: JSON.stringify(challenge) }] } });
    const response = await withGateway(client => client.callTool({ name: 'place_order', arguments: { product: 'risotto', quantity: 2 } }));
    expect(JSON.parse((response.content as Array<{ text: string }>)[0]!.text)).toEqual(challenge);
  });

  it('returns the exact payment checkout id with consent and resumes its saved protocol and handler', async () => {
    vi.stubEnv('COMMERCE_PAYMENTS', '1');
    const challenge = { error: 'needs_authorization', authorizationUrl: 'https://consent.example/consent?resume_token=approved-later', resumeToken: 'approved-later' };
    const checkoutId = 'agent-checkout-17';
    mocks.commerce.mockResolvedValueOnce({ ...result, checkoutId,
      result: { content: [{ type: 'text', text: JSON.stringify(challenge) }] } });
    await withGateway(async client => {
      const consent = await client.callTool({ name: 'place_order', arguments: { product: 'risotto', quantity: 2,
        payment_protocol: 'ucp', payment_method: 'sandbox-token' } });
      expect(JSON.parse((consent.content as Array<{ text: string }>)[0]!.text)).toEqual({ ...challenge, checkout_id: checkoutId });
      mocks.checkout.mockReturnValue({ id: checkoutId, protocol: 'ucp', rail: 'sandbox-token' });
      const resumed = await client.callTool({ name: 'place_order', arguments: { product: 'risotto', quantity: 2, checkout_id: checkoutId } });
      expect(resumed.isError).toBeFalsy();
      expect(mocks.commerce).toHaveBeenLastCalledWith({ product: 'risotto', quantity: 2, serverUrl: 'https://merchant.example/mcp',
        audience: 'did:key:merchant', paymentProtocol: 'ucp', paymentMethod: 'sandbox-token', checkoutId });
      expect(mocks.order).not.toHaveBeenCalled();
    });
  });
});
