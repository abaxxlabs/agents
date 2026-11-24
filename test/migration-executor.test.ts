import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createMockClient, createMockPool } from './mocks/pool.js';
import { MigrationExecutor } from '#identity/migration.js';
import { DidAliasRegistry } from '#did/alias.js';
import { AuditLogger } from '#audit/index.js';
import {
  MigrationTrustAnchor,
  UntrustedMigrationIssuerError,
  type TrustedMigrationCredential,
} from '#discovery/migration-trust-anchor.js';
import type { RegisteredAgent, MigrationCredentialClaims } from '#types/index.js';

const TEST_MIGRATION_ISSUER = 'did:dht:test-migration-issuer';

function createTrustedAnchor(): MigrationTrustAnchor {
  const anchor = new MigrationTrustAnchor();
  anchor.addFromParentCredentialChain(TEST_MIGRATION_ISSUER);
  return anchor;
}

function createMigrationFixtures(
  options: {
    aliasExists?: boolean;
    agentCount?: number;
    failOnStep?: 'begin' | 'insert-alias' | 'update-agents' | 'update-context' | 'commit';
  } = {},
) {
  const { aliasExists = false, agentCount = 2, failOnStep } = options;
  const clientQueries: string[] = [];

  const client = createMockClient((sql) => {
    clientQueries.push(sql);

    if (failOnStep === 'begin' && sql.includes('BEGIN'))
      throw new Error('simulated DB error on BEGIN');
    if (failOnStep === 'insert-alias' && sql.includes('INSERT INTO agent_did_aliases'))
      throw new Error('simulated DB error on alias INSERT');
    if (failOnStep === 'update-agents' && sql.includes('UPDATE agents'))
      throw new Error('simulated DB error on agent UPDATE');
    if (failOnStep === 'update-context' && sql.includes('UPDATE agent_context'))
      throw new Error('simulated DB error on context UPDATE');
    if (failOnStep === 'commit' && sql.includes('COMMIT'))
      throw new Error('simulated DB error on COMMIT');

    if (sql.includes('SELECT 1 FROM agent_did_aliases'))
      return { rows: aliasExists ? [{ '1': 1 }] : [] };
    if (sql.includes('SELECT COUNT')) return { rows: [{ cnt: String(agentCount) }] };
    if (sql.includes('INSERT INTO agent_did_aliases')) return { rowCount: 1 };
    if (sql.includes('UPDATE agents')) return { rowCount: agentCount };
    if (sql.includes('UPDATE agent_context')) return { rowCount: 5 };

    return { rows: [], rowCount: 0 };
  });

  return { pool: createMockPool({ client }), client, clientQueries };
}

function createMockAuditLogger() {
  return {
    logRejection: vi.fn().mockResolvedValue({
      id: 'audit-1',
      timestamp: new Date().toISOString(),
      agentDid: 'test',
      ownerDid: 'test',
      credentialId: 'none',
      queryHash: 'none',
      columnsAccessed: [],
      rowCount: 0,
      durationMs: 0,
      previousHash: 'GENESIS',
      signature: 'unsigned',
      version: 2,
      status: 'rejected',
    }),
  } as unknown as AuditLogger;
}

function makeClaims(overrides?: Partial<MigrationCredentialClaims>): MigrationCredentialClaims {
  return {
    previousDid: 'did:key:z6MkOldUser',
    oidcSubject: 'user@example.com',
    migrationMethod: 'oidc-verified',
    oidcIssuer: 'https://login.microsoftonline.com/tenant-abc',
    migratedAt: new Date().toISOString(),
    ...overrides,
  };
}

function makeTestJwt(opts: { iss?: string; nonce?: string } = {}): string {
  const header = { alg: 'EdDSA', typ: 'JWT' };
  const payload = { iss: opts.iss ?? TEST_MIGRATION_ISSUER, nonce: opts.nonce ?? 'default' };
  const b64u = (obj: object): string =>
    Buffer.from(JSON.stringify(obj), 'utf-8').toString('base64url');
  return `${b64u(header)}.${b64u(payload)}.fake-signature-not-verified-in-tests`;
}

describe('MigrationExecutor', () => {
  let registry: DidAliasRegistry;
  let agents: Map<string, RegisteredAgent>;
  const oldDid = 'did:key:z6MkOldUser';
  const newDid = 'did:dht:NewUserDHT';
  const credentialJwt = makeTestJwt() as TrustedMigrationCredential;

  beforeEach(() => {
    registry = new DidAliasRegistry();
    agents = new Map<string, RegisteredAgent>();
    agents.set('did:key:z6MkAgent1', {
      did: 'did:key:z6MkAgent1',
      ownerDid: oldDid,
      name: 'agent-1',
    } as RegisteredAgent);
    agents.set('did:key:z6MkAgent2', {
      did: 'did:key:z6MkAgent2',
      ownerDid: oldDid,
      name: 'agent-2',
    } as RegisteredAgent);
  });

  it('returns alreadyMigrated when credential hash is in the alias registry', async () => {
    const { pool } = createMigrationFixtures();
    const auditLogger = createMockAuditLogger();
    const executor = new MigrationExecutor({
      pool,
      agents,
      aliasRegistry: registry,
      auditLogger,
      migrationTrustAnchor: createTrustedAnchor(),
    });

    const crypto = await import('node:crypto');
    const hash = crypto.createHash('sha256').update(credentialJwt).digest('hex').slice(0, 16);
    registry.addAlias({
      oldDid,
      newDid,
      credentialHash: hash,
      migratedAt: new Date(),
      expiresAt: new Date(Date.now() + 86400000),
    });

    const result = await executor.execute(credentialJwt, makeClaims(), newDid);

    expect(result.success).toBe(true);
    expect(result.alreadyMigrated).toBe(true);
    expect(result.agentsMigrated).toBe(0);
    expect(result.aliasCreated).toBe(false);
    expect(pool.connect).not.toHaveBeenCalled();
  });

  it('executes full migration: DB updates, alias, and in-memory map', async () => {
    const { pool, clientQueries } = createMigrationFixtures({ agentCount: 2 });
    const auditLogger = createMockAuditLogger();
    const executor = new MigrationExecutor({
      pool,
      agents,
      aliasRegistry: registry,
      auditLogger,
      migrationTrustAnchor: createTrustedAnchor(),
    });

    const result = await executor.execute(credentialJwt, makeClaims(), newDid);

    expect(result.success).toBe(true);
    expect(result.alreadyMigrated).toBe(false);
    expect(result.aliasCreated).toBe(true);
    expect(result.agentsMigrated).toBe(2);
    expect(result.contextEntriesMigrated).toBe(5);
    expect(result.gracePeriodExpiresAt).toBeInstanceOf(Date);

    expect(clientQueries).toContain('BEGIN ISOLATION LEVEL SERIALIZABLE');
    expect(clientQueries).toContain('COMMIT');

    expect(registry.didsMatch(oldDid, newDid)).toBe(true);

    for (const [, agent] of agents) {
      expect(agent.ownerDid).toBe(newDid);
    }

    expect(auditLogger.logRejection).toHaveBeenCalledWith(
      expect.stringContaining('Identity migration'),
      'IDENTITY_MIGRATION',
      undefined,
      expect.objectContaining({
        agentDid: newDid,
        ownerDid: newDid,
      }),
    );
  });

  it('rolls back and throws on INSERT alias failure', async () => {
    const { pool, client } = createMigrationFixtures({ failOnStep: 'insert-alias' });
    const auditLogger = createMockAuditLogger();
    const executor = new MigrationExecutor({
      pool,
      agents,
      aliasRegistry: registry,
      auditLogger,
      migrationTrustAnchor: createTrustedAnchor(),
    });

    await expect(executor.execute(credentialJwt, makeClaims(), newDid)).rejects.toThrow(
      'simulated DB error on alias INSERT',
    );

    expect(client.query).toHaveBeenCalledWith('ROLLBACK');
    expect(registry.size).toBe(0);
    for (const [, agent] of agents) {
      expect(agent.ownerDid).toBe(oldDid);
    }
  });

  it('runs the trust anchor check BEFORE the idempotency check (does not leak migration history to untrusted issuers)', async () => {
    const { pool } = createMigrationFixtures();
    const auditLogger = createMockAuditLogger();
    const executor = new MigrationExecutor({
      pool,
      agents,
      aliasRegistry: registry,
      auditLogger,
      migrationTrustAnchor: createTrustedAnchor(),
    });

    const forkerJwt = makeTestJwt({ iss: 'did:dht:fork-org-issuer' }) as TrustedMigrationCredential;

    // Pre-seed the alias registry with the forker JWT's hash (simulates an unrelated prior migration).
    const crypto = await import('node:crypto');
    const hash = crypto.createHash('sha256').update(forkerJwt).digest('hex').slice(0, 16);
    registry.addAlias({
      oldDid,
      newDid,
      credentialHash: hash,
      migratedAt: new Date(),
      expiresAt: new Date(Date.now() + 86400000),
    });

    const hasCredentialSpy = vi.spyOn(registry, 'hasCredential');

    await expect(executor.execute(forkerJwt, makeClaims(), newDid)).rejects.toThrow(
      UntrustedMigrationIssuerError,
    );

    expect(hasCredentialSpy).not.toHaveBeenCalled();
    expect(pool.connect).not.toHaveBeenCalled();
  });
});
