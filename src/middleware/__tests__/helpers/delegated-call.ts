/**
 * Test helper: the delegated call the middleware tests make. A tool, the
 * scope that grants it and the consent that asks for it, the arguments it is
 * called with, and a handler to answer it.
 */
import type { KyaOsToolHandler } from '../../with-kya-os.js';

export const TOOL = 'records.read';
export const SCOPE = 'records:read';
export const CONSENT = { scopeId: SCOPE, consentUrl: 'https://consent.example/authorize' };
export const ARGS = { recordId: 'r-1' };

export const released: KyaOsToolHandler = async (args) => ({
  content: [{ type: 'text', text: `released ${String(args['recordId'])}` }],
});
