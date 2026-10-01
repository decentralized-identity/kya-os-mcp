import { createHandshakeRequest, type SessionManager } from '@kya-os/mcp';

/**
 * Private SDK context used only to sign the merchant's response evidence.
 * It is neither an MCP transport session nor a source of caller authority.
 *
 * The SDK's automatic context can race on concurrent first calls, and its
 * fallback becomes ambiguous after another handshake. Thread this explicit
 * context into proof wrappers instead. A shared promise also makes renewal
 * safe after the SDK's normal expiry checks invalidate the previous context.
 */
export class ResponseProofContext {
  private sessionId?: string;
  private pending?: Promise<string>;

  constructor(
    private readonly sessions: Pick<SessionManager, 'getSession' | 'validateHandshake'>,
    private readonly audience: string,
  ) {}

  getSessionId(): Promise<string> {
    this.pending ??= this.resolve().finally(() => { this.pending = undefined; });
    return this.pending;
  }

  private async resolve(): Promise<string> {
    if (this.sessionId && await this.sessions.getSession(this.sessionId)) return this.sessionId;
    this.sessionId = undefined;
    const result = await this.sessions.validateHandshake(createHandshakeRequest(this.audience));
    if (!result.success || !result.session) {
      throw new Error(`Response proof context unavailable: ${result.error?.message ?? 'SDK did not establish a context'}`);
    }
    this.sessionId = result.session.sessionId;
    return this.sessionId;
  }
}
