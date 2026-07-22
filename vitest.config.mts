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
    exclude: [...configDefaults.exclude, '**/.worktrees/**', '**/.claude/**'],
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      exclude: ['src/**/__tests__/**', 'src/**/index.ts'],
      thresholds: {
        lines: 80,
        branches: 75,
        functions: 80,
        statements: 80,
      },
    },
  },
});
