import { defineConfig } from 'vitest/config';
export default defineConfig({
  esbuild: { tsconfigRaw: { compilerOptions: { experimentalDecorators: true } } },
  test: { environment: 'node', include: ['tests/integration/redis-cluster/*.test.ts'], testTimeout: 30_000, hookTimeout: 60_000 },
});
