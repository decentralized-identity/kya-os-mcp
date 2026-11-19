import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  eslint.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ['src/**/*.ts'],
    ignores: ['**/__tests__/**', '**/*.test.ts'],
    languageOptions: {
      parser: tseslint.parser,
      parserOptions: {
        project: './tsconfig.json',
      },
    },
    rules: {
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
      '@typescript-eslint/explicit-function-return-type': ['error', {
        allowExpressions: true,
        allowTypedFunctionExpressions: true,
        allowHigherOrderFunctions: true,
      }],
      'preserve-caught-error': 'off',
      // zod's named `z` export holds the whole of zod, every locale among it, so a bundler keeps all
      // of it for any consumer that reaches the import (src/__tests__/bundled-zod.test.ts).
      'no-restricted-syntax': ['error', {
        selector: "ImportDeclaration[source.value='zod'] > ImportSpecifier[imported.name='z']",
        message: "Import zod as a namespace, `import * as z from 'zod'`: the named `z` export carries every zod locale into a consumer's bundle.",
      }],
    },
  },
  {
    // The adopter suite's runners are plain Node ESM, with the Node globals they use.
    files: ['adopters/*.mjs', 'adopters/runner/*.mjs'],
    languageOptions: {
      globals: { process: 'readonly', console: 'readonly', setTimeout: 'readonly', clearTimeout: 'readonly', Buffer: 'readonly' },
    },
  },
  {
    ignores: ['dist/**', 'examples/**', 'adopters/fixtures/**', '**/__tests__/**', '**/*.test.ts', '*.config.js'],
  }
);
