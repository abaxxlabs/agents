import { defineConfig } from 'vitest/config';

export const e2eTestInclude = [
  'test/e2e/**/*.test.ts',
  // Keystore stays in the default config so the skipped Keychain gate is visible
  // there, and is also included here so opt-in e2e runs execute real Keychain
  // coverage on a suitable macOS machine.
  'test/keystore.test.ts',
  // These suites are intentionally omitted from the default Vitest config:
  // they either require local services or bind loopback HTTP listeners.
  'test/integration/oidc-discovery.test.ts',
  'test/mock-oidc-server.test.ts',
  'test/jwks-verify.test.ts',
];

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: e2eTestInclude,
    passWithNoTests: true,
    testTimeout: 30_000,
  },
});
