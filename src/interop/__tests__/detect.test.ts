import { detectEnvelopeFormat } from '../detect.js';

describe('detectEnvelopeFormat', () => {
  it('detects a Google A2A envelope by agentCard', () => {
    expect(detectEnvelopeFormat({ agentCard: { name: 'x' } })).toBe('google-a2a');
  });

  it('detects a Google A2A envelope by message.parts', () => {
    expect(detectEnvelopeFormat({ message: { parts: [{ kind: 'text', text: 'hi' }] } })).toBe('google-a2a');
  });

  it('detects a Google A2A envelope by a google-shaped delegation block', () => {
    expect(detectEnvelopeFormat({ delegation: { issuer: 'a', subject: 'b' } })).toBe('google-a2a');
  });

  it('detects an Adobe A2A envelope', () => {
    expect(
      detectEnvelopeFormat({
        protocol: 'adobe-a2a',
        from: { did: 'a' },
        to: { did: 'b' },
        authorization: { delegationId: 'd', grants: [] },
      }),
    ).toBe('adobe-a2a');
  });

  it('detects a native KYA-OS delegation VC', () => {
    expect(
      detectEnvelopeFormat({
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiableCredential', 'DelegationCredential'],
        issuer: 'did:web:i',
        credentialSubject: { id: 'did:web:s', delegation: {} },
      }),
    ).toBe('kya-os-vc');
  });

  it.each([
    ['empty object', {}],
    ['null', null],
    ['number', 42],
    ['string', 'str'],
    ['array', []],
    ['undefined', undefined],
    ['boolean', true],
  ])('returns "unknown" for %s', (_label, input) => {
    expect(detectEnvelopeFormat(input)).toBe('unknown');
  });

  it('resolves VC-first when a payload carries overlapping VC + Google keys', () => {
    const overlapping = {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: ['VerifiableCredential', 'DelegationCredential'],
      agentCard: { name: 'decoy' },
      delegation: { issuer: 'a', subject: 'b' },
    };
    expect(detectEnvelopeFormat(overlapping)).toBe('kya-os-vc');
  });

  it('resolves Adobe-before-Google when a payload carries both authorization and a delegation block', () => {
    const overlapping = {
      from: { did: 'a' },
      to: { did: 'b' },
      authorization: { delegationId: 'd' },
      delegation: { issuer: 'a', subject: 'b' },
    };
    expect(detectEnvelopeFormat(overlapping)).toBe('adobe-a2a');
  });

  it('never throws on hostile or malformed input', () => {
    const hostile = JSON.parse('{"__proto__":{"x":1},"@context":42,"type":"nope"}');
    expect(() => detectEnvelopeFormat(hostile)).not.toThrow();
    expect(() => detectEnvelopeFormat(Symbol('s') as unknown)).not.toThrow();
    expect(() => detectEnvelopeFormat(BigInt(1) as unknown)).not.toThrow();
  });
});
