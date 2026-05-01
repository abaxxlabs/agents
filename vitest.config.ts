import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

const rootDir = fileURLToPath(new URL('.', import.meta.url));

export const defaultTestExclude = [
  'test/e2e/**',
  // Release-readiness: external-service and loopback-listener coverage is
  // explicit e2e coverage so `npm test` stays deterministic in restricted CI.
  'test/integration/oidc-discovery.test.ts',
  'test/mock-oidc-server.test.ts',
  'test/jwks-verify.test.ts',
];

export default defineConfig({
  resolve: {
    alias: [
      {
        find: /^@abaxxlabs\/agents\/storage\/postgres\/(.+)\.js$/,
        replacement: `${rootDir}src/storage/postgres/$1.ts`,
      },
      { find: '@abaxxlabs/agents/bootstrap', replacement: `${rootDir}src/bootstrap/index.ts` },
      { find: '@abaxxlabs/agents/sqlite', replacement: `${rootDir}src/storage/sqlite/index.ts` },
      { find: '@abaxxlabs/agents/storage', replacement: `${rootDir}src/storage/index.ts` },
      { find: '@abaxxlabs/agents/sql', replacement: `${rootDir}src/sql/index.ts` },
      { find: '@abaxxlabs/agents/mcp', replacement: `${rootDir}src/mcp/index.ts` },
      { find: '@abaxxlabs/agents', replacement: `${rootDir}src/index.ts` },
    ],
  },
  test: {
    globals: true,
    environment: 'node',
    include: ['test/**/*.test.ts'],
    exclude: defaultTestExclude,
    testTimeout: 30_000,
  },
});
