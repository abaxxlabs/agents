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

/**
 * Unified regression suite for AGENTS_* env coupling. No AGENTS_* vars are
 * read inside policy modules; configuration enters through typed config objects.
 */

import { describe, it, expect } from 'vitest';
import { loadConfig } from '../../src/config.js';
import { OrgBoundary } from '../../src/identity/org-boundary.js';
import { LocalTrustAnchorStore } from '../../src/discovery/trust-anchor.js';
import { createKeystore, JsonFileBackend } from '../../src/identity/keystore.js';
import type { AgentScopeConfig } from '../../src/types.js';
import type { ScopeMode } from '../../src/sql/scope-engine.js';
import { ScopeEngine } from '../../src/sql/scope-engine.js';
import { VcVerifier } from '../../src/vc-verifier.js';
import { InMemoryRevocationStore } from '../../src/storage/memory/revocation-store.js';
import { AuditLogger } from '../../src/audit-logger.js';
import type { AgentStore, AuditStore } from '../../src/storage/types.js';
import type { Pool } from 'pg';
import { generateDidKey } from '../../src/auth/index.js';
import { vi } from 'vitest';

const DB_URL = 'postgresql://test:test@localhost:54322/postgres';

/**
 * Snapshot helper — saves the current value of an env var so afterEach
 * cleanup can restore it precisely (including the unset case).
 */
function snapshotEnv(name: string): { restore: () => void } {
  const orig = process.env[name];
  return {
    restore: () => {
      if (orig === undefined) delete process.env[name];
      else process.env[name] = orig;
    },
  };
}

/**
 * Construct a minimal ScopeEngine — the validator gate is at construction
 * time, no DB I/O needed.
 */
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
  describe('AGENTS_DEV_MODE', () => {
    it('loadConfig validator does NOT honor AGENTS_DEV_MODE env var', () => {
      const snap = snapshotEnv('AGENTS_DEV_MODE');
      process.env.AGENTS_DEV_MODE = 'true';
      try {
        expect(() =>
          loadConfig({ database: { connectionString: DB_URL } } as AgentScopeConfig),
        ).toThrowError(/requires either abaxxOne or oidc/i);
      } finally {
        snap.restore();
      }
    });

    it('loadConfig validator: explicit devMode:true wins over env (which is ignored either way)', () => {
      const snap = snapshotEnv('AGENTS_DEV_MODE');
      process.env.AGENTS_DEV_MODE = 'false';
      try {
        expect(() =>
          loadConfig({
            database: { connectionString: DB_URL },
            devMode: true,
          }),
        ).not.toThrow();
      } finally {
        snap.restore();
      }
    });
  });

  describe('AGENTS_KEYSTORE_PATH', () => {
    it('createKeystore does NOT honor AGENTS_KEYSTORE_PATH env var', () => {
      const snap = snapshotEnv('AGENTS_KEYSTORE_PATH');
      const SENTINEL = '/tmp/SENTINEL-AGENTS_KEYSTORE_PATH-251.json';
      process.env.AGENTS_KEYSTORE_PATH = SENTINEL;
      const ciSnap = snapshotEnv('CI');
      process.env.CI = 'true';
      try {
        const backend = createKeystore();
        expect(backend).toBeInstanceOf(JsonFileBackend);
        expect((backend as unknown as { filePath: string }).filePath).not.toBe(SENTINEL);
      } finally {
        snap.restore();
        ciSnap.restore();
      }
    });

    it('createKeystore: explicit customPath wins; env still ignored', () => {
      const snap = snapshotEnv('AGENTS_KEYSTORE_PATH');
      const ciSnap = snapshotEnv('CI');
      const SENTINEL_ENV = '/tmp/SENTINEL-env-from-251.json';
      const EXPLICIT = '/tmp/explicit-251.json';
      process.env.AGENTS_KEYSTORE_PATH = SENTINEL_ENV;
      process.env.CI = 'true';
      try {
        const backend = createKeystore({ customPath: EXPLICIT });
        expect(backend).toBeInstanceOf(JsonFileBackend);
        expect((backend as unknown as { filePath: string }).filePath).toBe(EXPLICIT);
      } finally {
        snap.restore();
        ciSnap.restore();
      }
    });
  });

  describe('AGENTS_TRUSTED_SERVERS', () => {
    const OWN_DID = 'did:key:z6MkOwn-251';
    const SENTINEL_DID = 'did:key:z6MkSENTINEL-AGENTS_TRUSTED_SERVERS-251';
    const EXPLICIT_DID = 'did:key:z6MkExplicit-251';

    it('LocalTrustAnchorStore does NOT honor AGENTS_TRUSTED_SERVERS env var', () => {
      const snap = snapshotEnv('AGENTS_TRUSTED_SERVERS');
      process.env.AGENTS_TRUSTED_SERVERS = SENTINEL_DID;
      try {
        const store = new LocalTrustAnchorStore({ ownServerDid: OWN_DID });
        expect(store.list().length).toBe(1);
        expect(store.isTrusted(SENTINEL_DID)).toBe(false);
      } finally {
        snap.restore();
      }
    });

    it('LocalTrustAnchorStore: explicit initialTrustedServers wins; env still ignored', () => {
      const snap = snapshotEnv('AGENTS_TRUSTED_SERVERS');
      process.env.AGENTS_TRUSTED_SERVERS = SENTINEL_DID;
      try {
        const store = new LocalTrustAnchorStore({
          ownServerDid: OWN_DID,
          initialTrustedServers: [EXPLICIT_DID],
        });
        expect(store.list().length).toBe(2);
        expect(store.isTrusted(EXPLICIT_DID)).toBe(true);
        expect(store.isTrusted(SENTINEL_DID)).toBe(false);
      } finally {
        snap.restore();
      }
    });
  });

  describe('AGENTS_CONSUMER_DOMAINS', () => {
    it('OrgBoundary.extract does NOT honor AGENTS_CONSUMER_DOMAINS env var', () => {
      const snap = snapshotEnv('AGENTS_CONSUMER_DOMAINS');
      const SENTINEL_DOMAIN = 'sentinel-251.invalid';
      process.env.AGENTS_CONSUMER_DOMAINS = SENTINEL_DOMAIN;
      try {
        const result = OrgBoundary.extract({
          email: `alice@${SENTINEL_DOMAIN}`,
          claims: {},
        });
        expect(result.org).toBe(SENTINEL_DOMAIN);
        expect(result.isEnterprise).toBe(true);
      } finally {
        snap.restore();
      }
    });

    it('OrgBoundary.extract: explicit extraConsumerDomains wins; env still ignored', () => {
      const snap = snapshotEnv('AGENTS_CONSUMER_DOMAINS');
      const SENTINEL_FROM_ENV = 'env-only-251.invalid';
      const EXPLICIT_DOMAIN = 'explicit-251.invalid';
      process.env.AGENTS_CONSUMER_DOMAINS = SENTINEL_FROM_ENV;
      try {
        const a = OrgBoundary.extract({ email: `alice@${EXPLICIT_DOMAIN}`, claims: {} }, [
          EXPLICIT_DOMAIN,
        ]);
        expect(a.org).toBeNull();

        const b = OrgBoundary.extract({ email: `bob@${SENTINEL_FROM_ENV}`, claims: {} }, [
          EXPLICIT_DOMAIN,
        ]);
        expect(b.org).toBe(SENTINEL_FROM_ENV);
      } finally {
        snap.restore();
      }
    });
  });

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
