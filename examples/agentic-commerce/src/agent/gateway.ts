/**
 * The agent runtime Claude connects to at /agent/mcp on the merchant listener.
 *
 *   Claude (the brain, no keys)
 *     │  stateless MCP (Streamable HTTP)
 *     ▼
 *   THIS gateway (holds the agent's did:key + the delegation; signs every call)
 *     │  place_order + credential + Ed25519 holder proof   (streamable-http)
 *     ▼
 *   Merchant edge (withKyaOs verifier)
 *
 * Claude sees two tools, `browse_catalog` and `place_order`,
 * with no crypto arguments. The gateway injects the
 * credential and mints the per-request holder proof. The LLM never touches
 * key material: that is the point, and a talking point.
 *
 * npm run demo mounts both HTTP endpoints; each request gets a fresh MCP server.
 */
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { flag, merchantOrigin } from '../lib/wiring.js';
import { browseCatalog, runAgentOrder } from './agent.js';
import { responseBody } from './authorization.js';
import { readAgentCheckout } from './store.js';
import { isMainModule } from '../lib/main-module.js';
export function createGatewayServer(options: { merchantOrigin?: string; audience?: string } = {}): Server {
  const merchant = options.merchantOrigin ?? merchantOrigin();
  const paymentsEnabled = flag('COMMERCE_PAYMENTS');
  const server = new Server({ name: 'kya-shopping-agent', version: '0.1.0' }, { capabilities: { tools: {} } });

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      {
        name: 'browse_catalog',
        description: 'List the merchant\'s products (name, GS1 Digital Link URI, price). Open to any agent; no authority needed.',
        inputSchema: { type: 'object' as const, properties: {} },
      },
      {
        name: 'place_order',
        description: paymentsEnabled
          ? 'Order a catalog product with delegated authority. Human consent returns a verified authorizationUrl. Default order-only makes no payment; select x402 for signed payment or ucp for checkout with human review. Payment mode is configured by the operator: sandbox moves no funds, testnet uses test USDC only. For a continue_url, ask the human to review and confirm, then retry with checkout_id. Never approve on their behalf. An unresolved settlement must retain its checkout_id; do not create another payment.'
          : 'Place an order for a catalog product. If human consent is needed, returns a verified authorizationUrl to open and approve. After the human approves, retry within the approved product scope and per-order cap. The gateway attaches the new grant and a fresh holder proof. Returns an order receipt or a policy denial. This does not make a payment.',
        inputSchema: {
          type: 'object' as const,
          properties: {
            product: { type: 'string', description: 'Catalog sku (e.g. "risotto") or a GS1 Digital Link URI' },
            quantity: { type: 'integer', minimum: 1, description: 'How many units (default 1)' },
            ...(paymentsEnabled ? {
              payment_protocol: { type: 'string', enum: ['order-only', 'x402', 'ucp'], description: 'Order-only (default), x402 payment, or UCP checkout' },
              payment_method: { type: 'string', enum: ['x402', 'sandbox-token'], description: 'UCP payment handler; x402 is the default. sandbox-token is an explicit simulation.' },
              checkout_id: { type: 'string', description: 'Resume the returned checkout after consent, human review, or a connection interruption. Its saved protocol and payment handler are reused when omitted.' },
            } : {}),
          },
          required: ['product'],
        },
      },
    ],
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args = {} } = request.params;
    try {
      if (name === 'browse_catalog') {
        const items = (await browseCatalog(`${merchant}/mcp`)) as Array<{ sku: string; name: string; uri: string; unitPrice: string; currency: string }>;
        return { content: [{ type: 'text', text: items.map((i) => `- ${i.sku}: ${i.name} — ${i.currency} ${i.unitPrice} — ${i.uri}`).join('\n') }] };
      }
      if (name === 'place_order') {
        // Never downgrade a payment intent into an unpaid order. The default
        // workshop contract also avoids reading any checkout or wallet state.
        if (!paymentsEnabled && ['payment_protocol', 'payment_method', 'checkout_id'].some(key => Object.hasOwn(args, key))) {
          throw new Error('PAYMENTS_DISABLED: payment checkouts require the operator to enable COMMERCE_PAYMENTS=1');
        }
        const product = String((args as Record<string, unknown>)['product'] ?? '');
        const quantity = Number((args as Record<string, unknown>)['quantity'] ?? 1);
        const checkoutId = args['checkout_id'];
        if (checkoutId !== undefined && (typeof checkoutId !== 'string' || !checkoutId)) throw new Error('CHECKOUT_INVALID: provide the returned checkout_id');
        const saved = typeof checkoutId === 'string' ? readAgentCheckout(checkoutId) : null;
        if (checkoutId !== undefined && !saved) throw new Error('CHECKOUT_NOT_FOUND: this agent does not own that checkout');
        const protocol = args['payment_protocol'] ?? saved?.protocol ?? 'order-only';
        const method = args['payment_method'] ?? saved?.rail ?? 'x402';
        if (!['order-only', 'x402', 'ucp'].includes(String(protocol)) || !['x402', 'sandbox-token'].includes(String(method))) throw new Error('Unsupported payment protocol or method');
        if (protocol === 'order-only' && (checkoutId !== undefined || args['payment_method'] !== undefined)) throw new Error('CHECKOUT_BINDING_MISMATCH: a payment checkout cannot become an order-only request');
        const outcome = protocol === 'order-only'
          ? await runAgentOrder({ product, quantity, serverUrl: `${merchant}/mcp`, audience: options.audience })
          : await (await import('./commerce.js')).runAgentCommerce({ product, quantity, serverUrl: `${merchant}/mcp`, audience: options.audience,
            paymentProtocol: protocol as 'x402' | 'ucp', paymentMethod: method as 'x402' | 'sandbox-token',
            ...(typeof checkoutId === 'string' ? { checkoutId } : {}) });
        const text = outcome.result.content?.[0]?.text ?? '{}';
        const body = responseBody(outcome.result);
        if (body['error'] === 'needs_authorization') {
          // runAgentOrder has verified the merchant signature and every URL binding.
          // Retain paid intent across the human handoff so a checkout-id-only
          // retry cannot silently become the default unpaid order path.
          const checkoutId = protocol === 'order-only' ? undefined : outcome.checkoutId;
          return { content: [{ type: 'text', text: JSON.stringify({ ...body, ...(checkoutId ? { checkout_id: checkoutId } : {}) }, null, 2) }] };
        }
        if (body['continue_url'] || body['error'] === 'SETTLEMENT_PENDING') {
          const checkoutId = body['checkoutId'] ?? outcome.checkoutId;
          return { ...(body['error'] ? { isError: true } : {}), content: [{ type: 'text', text: JSON.stringify({ ...body, ...(checkoutId ? { checkout_id: checkoutId } : {}) }, null, 2) }] };
        }
        if (outcome.result.isError || body['error']) {
          const code = String(body['error'] ?? 'refused');
          const reason = String(body['reason'] ?? body['message'] ?? text);
          const hint = /revoked/i.test(reason) ? 'Your authority has been revoked by your owner. Nothing was ordered; ask them for a new delegation.'
            : code === 'PRODUCT_OUT_OF_SCOPE' ? 'That product is outside the product class you were delegated. Nothing was ordered.'
            : code === 'SPEND_CAP_EXCEEDED' ? 'That total exceeds your per-order cap. Nothing was ordered; try a smaller quantity.'
            : 'Nothing was ordered.';
          return { isError: true, content: [{ type: 'text', text: `Order refused (${code}): ${reason}\n${hint}` }] };
        }
        const o = body['order'] as Record<string, unknown>;
        const payment = body['payment'] as Record<string, unknown> | undefined;
        const paymentText = protocol === 'order-only' ? '' : `\nPayment: ${String(payment?.['status'] ?? 'unknown')}${payment?.['simulated'] === true ? ' (sandbox, no funds moved)' : ' (Base Sepolia testnet)'}. Checkout: ${String(body['checkoutId'])}.`;
        return { content: [{ type: 'text', text: `Order ${String(body['orderId'])} placed: ${String(o['quantity'])} × ${String(o['name'])} = ${String(o['total'])}.\nThe merchant verified your delegation (signature, revocation, holder key, product class, cap) and returned a signed receipt.${paymentText}` }] };
      }
    } catch (err) {
      return { isError: true, content: [{ type: 'text', text: `Gateway error reaching the merchant: ${err instanceof Error ? err.message : String(err)}` }] };
    }
    return { content: [{ type: 'text', text: `Unknown tool: ${name}` }], isError: true };
  });
  return server;
}

if (isMainModule(import.meta.url)) {
  process.stderr.write(`This gateway uses Streamable HTTP. Run npm run demo, then connect to ${merchantOrigin()}/agent/mcp. See ${merchantOrigin()}/connect. Remove the old stdio client entry.\n`);
  process.exitCode = 1;
}
