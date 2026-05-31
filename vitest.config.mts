import { defineConfig, configDefaults } from 'vitest/config';

export default defineConfig({
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
