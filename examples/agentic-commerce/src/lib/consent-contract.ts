/** Public messages shared by the three parties; no persistence dependencies. */
export interface ConsentBindings {
  agentDid: string;
  audience: string;
  product: string;
  quantity: number;
  productClass: string;
  cap: string;
  currency: string;
  validHours: number;
  authorizationOrigin?: string;
  requestHash?: string;
}
export interface ConsentChallenge {
  error: 'needs_authorization';
  message: string;
  authorizationUrl: string;
  resumeToken: string;
  expiresAt: number;
  scopes: string[];
  display: { title: string; hint: Array<'link'> };
}
