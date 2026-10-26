import { createRequire } from 'node:module';
import { defineConfig } from 'vitest/config';

// Resolve the API workspace dependencies even when npm keeps them nested.
const apiRequire = createRequire(new URL('./apps/console-api/package.json', import.meta.url));

export default defineConfig({
  resolve: {
    alias: {
      '@nestjs/common': apiRequire.resolve('@nestjs/common'),
      '@nestjs/core': apiRequire.resolve('@nestjs/core'),
    },
  },
  esbuild: {
    tsconfigRaw: { compilerOptions: { experimentalDecorators: true } },
  },
  test: {
    environment: 'node',
    include: ['tests/unit/**/*.test.ts', 'tests/security/**/*.test.ts'],
    // lab-evidence suites assert on raw lab evidence that is not published; run manually.
    exclude: ['**/node_modules/**', 'tests/**/lab-evidence/**'],
    testTimeout: 10_000,
    restoreMocks: true,
    clearMocks: true,
  },
});
