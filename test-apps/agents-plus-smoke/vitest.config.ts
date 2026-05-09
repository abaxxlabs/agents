/**
 * Vitest config for the consumer smoke app.
 *
 * Kept local to this app so it can be run independently from the parent
 * package's unit suite. The app uses real Postgres I/O, so tests are serial by
 * default through a single test file rather than a broad parallel matrix.
 */
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['test/**/*.test.ts'],
    testTimeout: 30_000,
  },
});
