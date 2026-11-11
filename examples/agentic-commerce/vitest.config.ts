import { defineConfig } from 'vitest/config';

// Tests qualify explicit identity fixtures, independent of the operator's live
// Google configuration in .env.local. Child-process tests inherit this value.
export default defineConfig({ test: { env: { GOOGLE_CLIENT_ID: '' } } });
