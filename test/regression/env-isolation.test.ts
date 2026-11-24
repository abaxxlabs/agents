import { describe, it, expect } from 'vitest';
import { loadConfig } from '#config.js';
import { OrgBoundary } from '#identity/org-boundary.js';
import { LocalTrustAnchorStore } from '#discovery/trust-anchor.js';
import type { ScopeMode } from '#sql/scope-engine.js';
import { ScopeEngine } from '#sql/scope-engine.js';
import { VcVerifier } from '#identity/index.js';
import { InMemoryRevocationStore } from '#storage/memory/revocation-store.js';
import { AuditLogger } from '#audit/index.js';
import type { AgentStore, AuditStore } from '#storage/types.js';
import type { Pool } from 'pg';
import { generateDidKey } from '#auth/index.js';
import { vi } from 'vitest';

const DB_URL = 'postgresql://test:test@localhost:54322/postgres';

function snapshotEnv(name: string): { restore: () => void } {
  const orig = process.env[name];
  return {
    restore: () => {
      if (orig === undefined) delete process.env[name];
      else process.env[name] = orig;
    },
  };
}

// Validation runs at construction, so these options need no database connection.
function minimalEngineOpts() {
  const server = generateDidKey();
  const verifier = new VcVerifier({
    clockSkew: '30s',
    revocationStore: new InMemoryRevocationStore(),
  });
  verifier.registerKey(server.did, server.publicKey);
  const noopStore: AuditStore = {
    append: vi.fn().mockResolvedValue(undefined),
    loadLastRecord: vi.fn().mockResolvedValue(null),
    loadLastRecordLocked: vi.fn().mockResolvedValue(null),
    query: vi.fn().mockResolvedValue([]),
    count: vi.fn().mockResolvedValue(0),
  };
  const pool = { query: vi.fn() } as unknown as Pool;
  const auditLogger = new AuditLogger({ auditStore: noopStore, enabled: false });
  return {
    pool,
    verifier,
    auditLogger,
    columnKeys: new Map<string, Buffer>(),
    encryptedColumns: new Set<string>(),
    agents: new Map(),
    verifierDid: server.did,
    agentStore: { findByDid: vi.fn().mockResolvedValue(null) } as unknown as AgentStore,
  };
}

describe('env-isolation regression suite', () => {
  describe('cross-cutting: all 4 env vars set, library runs cleanly with explicit config', () => {
    it('explicit config wins across all four migrated env vars simultaneously', () => {
      const snaps = [
        snapshotEnv('AGENTS_DEV_MODE'),
        snapshotEnv('AGENTS_KEYSTORE_PATH'),
        snapshotEnv('AGENTS_TRUSTED_SERVERS'),
        snapshotEnv('AGENTS_CONSUMER_DOMAINS'),
      ];
      process.env.AGENTS_DEV_MODE = 'true';
      process.env.AGENTS_KEYSTORE_PATH = '/tmp/SENTINEL-cross-cutting.json';
      process.env.AGENTS_TRUSTED_SERVERS = 'did:key:z6MkCrossCuttingSentinel-251';
      process.env.AGENTS_CONSUMER_DOMAINS = 'cross-cutting-sentinel-251.invalid';
      try {
        const merged = loadConfig({
          database: { connectionString: DB_URL },
          abaxxOne: { tenantUrl: 'http://localhost:3001', clientId: 'x' },
          devMode: false,
        });
        expect(merged.devMode).toBe(false);

        expect(
          () =>
            new ScopeEngine({
              ...minimalEngineOpts(),
              scopeMode: 'encryption-only' as unknown as ScopeMode,
            }),
        ).toThrowError(/Invalid scopeMode/);

        const store = new LocalTrustAnchorStore({ ownServerDid: 'did:key:z6Mk-cross-251' });
        expect(store.isTrusted('did:key:z6MkCrossCuttingSentinel-251')).toBe(false);

        const result = OrgBoundary.extract({
          email: 'alice@cross-cutting-sentinel-251.invalid',
          claims: {},
        });
        expect(result.org).toBe('cross-cutting-sentinel-251.invalid');
      } finally {
        for (const s of snaps) s.restore();
      }
    });
  });
});
