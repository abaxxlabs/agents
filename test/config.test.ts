// Copyright 2026 Abaxx Technologies
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Unit tests for loadConfig: validator branches, devMode, and field round-trips.

import { describe, it, expect } from 'vitest';
import { loadConfig, parseDuration } from '../src/config.js';
import type { AgentScopeConfig } from '../src/types.js';

const DB = { connectionString: 'postgresql://test:test@localhost:54322/postgres' };

describe('loadConfig — auth provider validation', () => {
  it('rejects config with neither abaxxOne nor oidc when devMode is unset', () => {
    expect(() => loadConfig({ database: DB } as AgentScopeConfig)).toThrowError(
      /requires either abaxxOne or oidc/i,
    );
  });

  it('rejects config with neither abaxxOne nor oidc when devMode is false', () => {
    expect(() => loadConfig({ database: DB, devMode: false } as AgentScopeConfig)).toThrowError(
      /requires either abaxxOne or oidc/i,
    );
  });

  it('accepts config with neither abaxxOne nor oidc when devMode: true', () => {
    expect(() => loadConfig({ database: DB, devMode: true })).not.toThrow();
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

describe('loadConfig — devMode env-read drift prevention', () => {
  it('does NOT honor process.env.AGENTS_DEV_MODE (library no longer reads it)', () => {
    const orig = process.env.AGENTS_DEV_MODE;
    process.env.AGENTS_DEV_MODE = 'true';
    try {
      expect(() => loadConfig({ database: DB } as AgentScopeConfig)).toThrowError(
        /requires either abaxxOne or oidc/i,
      );
    } finally {
      if (orig === undefined) delete process.env.AGENTS_DEV_MODE;
      else process.env.AGENTS_DEV_MODE = orig;
    }
  });
});

describe('loadConfig — devMode merged-output preservation', () => {
  it('merged output has devMode: true when raw input is devMode: true', () => {
    const merged = loadConfig({ database: DB, devMode: true });
    expect(merged.devMode).toBe(true);
  });

  it('merged output has devMode: false when raw input is devMode: false (with provider)', () => {
    const merged = loadConfig({
      database: DB,
      abaxxOne: { tenantUrl: 'http://localhost:3001', clientId: 'x' },
      devMode: false,
    });
    expect(merged.devMode).toBe(false);
  });

  it('merged output has devMode: false when raw input omits devMode (always boolean)', () => {
    const merged = loadConfig({
      database: DB,
      abaxxOne: { tenantUrl: 'http://localhost:3001', clientId: 'x' },
    });
    expect(merged.devMode).toBe(false);
  });

  it('strict === true: truthy non-boolean inputs are coerced to false', () => {
    expect(() => loadConfig({ database: DB, devMode: 'true' as unknown as boolean })).toThrowError(
      /requires either abaxxOne or oidc/i,
    );
  });
});

describe('loadConfig — keystore.path field', () => {
  it('round-trips keystore.path when set', () => {
    const merged = loadConfig({
      database: DB,
      abaxxOne: { tenantUrl: 'http://localhost:3001', clientId: 'x' },
      keystore: { path: '/custom/keystore.json' },
    });
    expect(merged.keystore?.path).toBe('/custom/keystore.json');
  });

  it('omits keystore field when not set (no implicit defaults)', () => {
    const merged = loadConfig({
      database: DB,
      abaxxOne: { tenantUrl: 'http://localhost:3001', clientId: 'x' },
    });
    expect(merged.keystore).toBeUndefined();
  });
});

describe('loadConfig — scopeMode', () => {
  const base = {
    database: DB,
    abaxxOne: { tenantUrl: 'http://localhost:3001', clientId: 'x' },
  } as const;

  it('omits scopeMode from merged output when unset (default projection at runtime)', () => {
    const merged = loadConfig(base);
    expect(merged.scopeMode).toBeUndefined();
  });
});

describe('loadConfig — orgBoundary.extraConsumerDomains field', () => {
  it('round-trips extraConsumerDomains when set', () => {
    const merged = loadConfig({
      database: DB,
      abaxxOne: { tenantUrl: 'http://localhost:3001', clientId: 'x' },
      orgBoundary: { extraConsumerDomains: ['contractor.com', 'freelance.io'] },
    });
    expect(merged.orgBoundary?.extraConsumerDomains).toEqual(['contractor.com', 'freelance.io']);
  });

  it('omits orgBoundary field when not set (no implicit defaults)', () => {
    const merged = loadConfig({
      database: DB,
      abaxxOne: { tenantUrl: 'http://localhost:3001', clientId: 'x' },
    });
    expect(merged.orgBoundary).toBeUndefined();
  });

  it('filters out non-string entries (defends against malformed JSON-parsed configs)', () => {
    const merged = loadConfig({
      database: DB,
      abaxxOne: { tenantUrl: 'http://localhost:3001', clientId: 'x' },
      orgBoundary: {
        extraConsumerDomains: [
          'contractor.com',
          42 as unknown as string,
          null as unknown as string,
          'freelance.io',
        ],
      },
    });
    expect(merged.orgBoundary?.extraConsumerDomains).toEqual(['contractor.com', 'freelance.io']);
  });

  it('does NOT honor AGENTS_CONSUMER_DOMAINS env var (drift-prevention for loadConfig)', () => {
    const orig = process.env.AGENTS_CONSUMER_DOMAINS;
    process.env.AGENTS_CONSUMER_DOMAINS = 'leaked.com,from.env';
    try {
      const merged = loadConfig({
        database: DB,
        abaxxOne: { tenantUrl: 'http://localhost:3001', clientId: 'x' },
      });
      expect(merged.orgBoundary).toBeUndefined();
    } finally {
      if (orig === undefined) delete process.env.AGENTS_CONSUMER_DOMAINS;
      else process.env.AGENTS_CONSUMER_DOMAINS = orig;
    }
  });
});

describe('parseDuration', () => {
  it.each([
    ['30s', 30_000],
    ['5m', 300_000],
    ['2h', 7_200_000],
    ['1d', 86_400_000],
    ['0s', 0],
  ])('parses simple %s → %i ms', (input, expected) => {
    expect(parseDuration(input)).toBe(expected);
  });

  // Millisecond unit
  it('parses 500ms → 500', () => expect(parseDuration('500ms')).toBe(500));
  it('parses 1ms → 1', () => expect(parseDuration('1ms')).toBe(1));

  // Fractional values
  it('parses 1.5s → 1500', () => expect(parseDuration('1.5s')).toBe(1500));
  it('parses 0.5m → 30000', () => expect(parseDuration('0.5m')).toBe(30_000));
  it('parses 1.5d → 129600000', () => expect(parseDuration('1.5d')).toBe(129_600_000));

  // Compound forms
  it('parses 1m30s → 90000', () => expect(parseDuration('1m30s')).toBe(90_000));
  it('parses 2h15m → 8100000', () => expect(parseDuration('2h15m')).toBe(8_100_000));
  it('parses 1d2h → 93600000', () => expect(parseDuration('1d2h')).toBe(93_600_000));

  // Invalid — must throw
  it('rejects bare number with no unit', () => {
    expect(() => parseDuration('90')).toThrow(/Invalid duration format/);
  });
  it('rejects unknown unit', () => {
    expect(() => parseDuration('5w')).toThrow(/Invalid duration format/);
  });
  it('rejects trailing garbage', () => {
    expect(() => parseDuration('30sx')).toThrow(/Invalid duration format/);
  });
  it('rejects empty string', () => {
    expect(() => parseDuration('')).toThrow(/Invalid duration format/);
  });
  it('rejects duplicate units', () => {
    expect(() => parseDuration('1m1m')).toThrow(/Duplicate unit/);
  });

  // Large durations would produce unsafe-integer ms or Infinity, disabling expiry checks.
  it('rejects durations above ~100 years', () => {
    expect(() => parseDuration('99999999999d')).toThrow(/out of range/);
    expect(() => parseDuration('1000000d')).toThrow(/out of range/);
  });

  it('rejects durations that overflow to Infinity', () => {
    expect(() => parseDuration('9'.repeat(400) + 'd')).toThrow(/out of range/);
  });

  it('accepts durations up to the 100-year cap', () => {
    expect(parseDuration('10950d')).toBe(10950 * 86_400_000);
  });
});
