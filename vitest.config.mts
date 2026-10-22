import { fileURLToPath } from 'node:url';
import { defineConfig, configDefaults } from 'vitest/config';

export default defineConfig({
  resolve: {
    alias: [
      // The example packages import this library by its published name. Vite 8's
      // resolver no longer falls back to the repo root for a name that only a
      // parent package.json declares, so pin both ids to the source entry
      // points; this also keeps example tests exercising src/ instead of a
      // possibly stale dist/ build.
      {
        find: /^@kya-os\/mcp\/authz$/,
        replacement: fileURLToPath(new URL('./src/authz/index.ts', import.meta.url)),
      },
      {
        find: /^@kya-os\/mcp\/cheqd$/,
        replacement: fileURLToPath(new URL('./src/integrations/cheqd/index.ts', import.meta.url)),
      },
      {
        find: /^@kya-os\/mcp$/,
        replacement: fileURLToPath(new URL('./src/index.ts', import.meta.url)),
      },
    ],
  },
  test: {
    environment: 'node',
    globals: true,
    // Run only the main working tree: skip any nested git worktrees a
    // contributor may have checked out under these dirs (each holds a full repo
    // copy whose tests would otherwise be collected twice). No-op on a clean
    // checkout / CI, where these dirs do not exist.
    exclude: [
      ...configDefaults.exclude,
      '**/.worktrees/**',
      '**/.claude/**',
      // A standalone app with its own dependencies (hono, WebAuthn, the
      // published package) and its own vitest run — `cd examples/agentic-commerce
      // && npm install && npm test`. Collecting it here would need those
      // dependencies at the repo root.
      'examples/agentic-commerce/**',
    ],
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      // vitest 4's coverage matching pulls in example-workspace sources loaded
      // through the resolver aliases; the gate measures the library only.
      exclude: ['src/**/__tests__/**', 'src/**/index.ts', 'examples/**'],
      // Ratcheted 2026-07-22 against the vitest 4 (ast-remapped) baseline of
      // 93.4 / 87.4 / 95.8 / 94.2 - a couple of points of headroom for
      // legitimate refactors, tight enough that a real coverage regression
      // fails the gate. Ratchet again rather than lowering.
      thresholds: {
        lines: 92,
        branches: 85,
        functions: 93,
        statements: 91,
      },
    },
  },
});
