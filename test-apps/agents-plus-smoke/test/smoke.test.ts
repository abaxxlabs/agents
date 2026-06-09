/**
 * Vitest wrapper for the consumer smoke app.
 *
 * This is intentionally one end-to-end assertion instead of many unit tests:
 * the app is meant to prove that a real consumer can install Agents++, prepare
 * a database, issue credentials, execute scoped SQL, and observe the expected
 * failure mode for overscope access.
 */
import { describe, expect, it } from 'vitest';
import {
  DEFAULT_DATABASE_URL,
  ENCRYPTED_COLUMNS,
  createSetupPool,
} from '../src/schema.js';
import { runSmoke } from '../src/smoke.js';

const databaseUrl = process.env.DATABASE_URL ?? DEFAULT_DATABASE_URL;
let postgresReachable = false;
try {
  const pool = createSetupPool(databaseUrl);
  const timeout = new Promise((_, reject) =>
    setTimeout(() => reject(new Error('probe timeout')), 5_000),
  );
  await Promise.race([pool.query('SELECT 1'), timeout]);
  await pool.end();
  postgresReachable = true;
} catch {
  postgresReachable = false;
}

const describeFn = postgresReachable ? describe : describe.skip;

describeFn('agents-plus-smoke', () => {
  it('runs scoped SQL access and blocks overscope queries', async () => {
    const result = await runSmoke({ databaseUrl, verbose: false });

    expect(result.overscopeBlocked).toBe(true);
    expect(result.fullAccessRows[0]).toMatchObject({
      desk: 'North America',
      symbol: 'ABXX',
      notional: '1250000',
      counterparty: 'ALPHA-CAP',
      strategy: 'basis-arbitrage',
    });
    expect(result.limitedRows[0]).toEqual({
      desk: 'North America',
      symbol: 'ABXX',
      notional: '1250000',
    });
    expect(result.auditRecordCount).toBeGreaterThanOrEqual(3);
    expect(result.encryptedColumns).toEqual([...ENCRYPTED_COLUMNS].sort());
  });
});
