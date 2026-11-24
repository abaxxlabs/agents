import { describe, it, expect } from 'vitest';
import { loadConfig, parseDuration } from '#config.js';
import type { AgentScopeConfig } from '#types/index.js';

const DB = { connectionString: 'postgresql://test:test@localhost:54322/postgres' };

describe('loadConfig — auth provider validation', () => {
  it('rejects config with neither abaxxOne nor oidc when devMode is unset', () => {
    expect(() => loadConfig({ database: DB } as AgentScopeConfig)).toThrowError(
      /requires either abaxxOne or oidc/i,
    );
  });

  it('rejects when both abaxxOne AND oidc are set (mutually exclusive)', () => {
    expect(() =>
      loadConfig({
        database: DB,
        abaxxOne: { tenantUrl: 'http://localhost:3001', clientId: 'x' },
        oidc: { issuerUrl: 'http://localhost:3002', clientId: 'y' },
      }),
    ).toThrowError(/cannot have both/i);
  });
});
describe('parseDuration', () => {
  // Large durations would produce unsafe-integer ms or Infinity, disabling expiry checks.
  it('rejects durations above ~100 years', () => {
    expect(() => parseDuration('99999999999d')).toThrow(/out of range/);
    expect(() => parseDuration('1000000d')).toThrow(/out of range/);
  });
});
