/**
 * Vitest wrapper for the consumer smoke app.
 *
 * This is intentionally one end-to-end assertion instead of many unit tests:
 * the app is meant to prove that a real consumer can install Agents++, prepare
 * a database, issue credentials, execute scoped SQL, and observe the expected
 * failure mode for overscope access.
 */
import { describe, expect, it } from 'vitest';
import { ENCRYPTED_COLUMNS } from '../src/schema.js';
import { runSmoke } from '../src/smoke.js';

describe('agents-plus-smoke', () => {
  it('runs scoped SQL access and blocks overscope queries', async () => {
    const result = await runSmoke({ verbose: false });

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
