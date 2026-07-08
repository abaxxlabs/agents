import { describe, it, expect, vi, beforeEach, type Mock } from 'vitest';
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

/**
 * Test migration issuer DID used by the happy-path tests below.
 *
 * In production, this set is sourced from the build-time-baked
 * OFFICIAL_MIGRATION_ISSUERS constant in migration-trust-anchor.ts (default
 * empty in OSS source). Tests use the public `addFromParentCredentialChain()`
 * method on a fresh `MigrationTrustAnchor` to whitelist this single test DID
 * — the same API a paid-tier consumer would use after verifying an AbaxxOne
 * parent credential. There is no test-only override path.
 */
const TEST_MIGRATION_ISSUER = 'did:dht:test-migration-issuer';

/**
 * Build a `MigrationTrustAnchor` that trusts `TEST_MIGRATION_ISSUER` only.
 * Used by tests that exercise the accepting path of `MigrationExecutor.execute()`.
 */
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
    if (sql.includes('SELECT COUNT'))
      return { rows: [{ cnt: String(agentCount) }] };
    if (sql.includes('INSERT INTO agent_did_aliases'))
      return { rowCount: 1 };
    if (sql.includes('UPDATE agents'))
      return { rowCount: agentCount };
    if (sql.includes('UPDATE agent_context'))
      return { rowCount: 5 };

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

/**
 * Build a real-format compact-JWS test JWT.
 *
 * MigrationExecutor.execute() decodes the issuer DID from
 * the JWT itself rather than accepting it as a separate parameter. Tests
 * therefore need real-format JWTs (`b64u(header).b64u(payload).<sig>`) with
 * a real `iss` claim — fake placeholder strings like `'eyJ.migration.credential'`
 * fail JWT decoding.
 *
 * The signature segment is intentionally a fixed string — the executor does
 * NOT verify signatures (signature verification is upstream caller responsibility).
 * To produce a JWT with a different idempotency hash, change `nonce` so the
 * payload (and thus the encoded JWT) differs byte-by-byte.
 */
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

    // Pre-populate the registry with a matching credential hash.
    // The hash is SHA-256 of the JWT, truncated to 16 hex chars.
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
    // Should NOT have touched the database
    expect(pool.connect).not.toHaveBeenCalled();
  });


  it('rejects previousDid that is not did:key', async () => {
    const { pool } = createMigrationFixtures();
    const auditLogger = createMockAuditLogger();
    const executor = new MigrationExecutor({
      pool,
      agents,
      aliasRegistry: registry,
      auditLogger,
      migrationTrustAnchor: createTrustedAnchor(),
    });

    await expect(
      executor.execute(credentialJwt, makeClaims({ previousDid: 'did:dht:NotAKey' }), newDid),
    ).rejects.toThrow('must be a did:key');
  });

  it('rejects newDid that is not did:dht', async () => {
    const { pool } = createMigrationFixtures();
    const auditLogger = createMockAuditLogger();
    const executor = new MigrationExecutor({
      pool,
      agents,
      aliasRegistry: registry,
      auditLogger,
      migrationTrustAnchor: createTrustedAnchor(),
    });

    await expect(
      executor.execute(credentialJwt, makeClaims(), 'did:key:z6MkNotDHT'),
    ).rejects.toThrow('must be a did:dht');
  });


  it('returns alreadyMigrated when credential is found in DB during transaction', async () => {
    const { pool } = createMigrationFixtures({ aliasExists: true });
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
    expect(result.alreadyMigrated).toBe(true);
  });


  it('throws when previousDid has no agents registered', async () => {
    const { pool } = createMigrationFixtures({ agentCount: 0 });
    const auditLogger = createMockAuditLogger();
    const executor = new MigrationExecutor({
      pool,
      agents,
      aliasRegistry: registry,
      auditLogger,
      migrationTrustAnchor: createTrustedAnchor(),
    });

    await expect(executor.execute(credentialJwt, makeClaims(), newDid)).rejects.toThrow(
      'has no agents registered',
    );
  });


  it('throws PrecisionLossError when COUNT exceeds MAX_SAFE_INTEGER', async () => {
    const unsafeCount = (BigInt(Number.MAX_SAFE_INTEGER) + 1n).toString();
    const client = createMockClient((sql) => {
      if (sql.includes('BEGIN')) return {};
      if (sql.includes('SELECT 1 FROM agent_did_aliases')) return { rows: [] };
      if (sql.includes('SELECT COUNT')) return { rows: [{ cnt: unsafeCount }] };
      return { rows: [], rowCount: 0 };
    });
    const pool = createMockPool({ client });

    const auditLogger = createMockAuditLogger();
    const executor = new MigrationExecutor({
      pool,
      agents,
      aliasRegistry: registry,
      auditLogger,
      migrationTrustAnchor: createTrustedAnchor(),
    });

    await expect(executor.execute(credentialJwt, makeClaims(), newDid)).rejects.toThrow(
      'exceeds Number.MAX_SAFE_INTEGER',
    );
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

    // Verify SERIALIZABLE isolation was used
    expect(clientQueries).toContain('BEGIN ISOLATION LEVEL SERIALIZABLE');
    expect(clientQueries).toContain('COMMIT');

    // Verify alias registry was updated
    expect(registry.didsMatch(oldDid, newDid)).toBe(true);

    // Verify in-memory agents map was updated
    for (const [, agent] of agents) {
      expect(agent.ownerDid).toBe(newDid);
    }

    // Verify audit log was called
    expect(auditLogger.logRejection).toHaveBeenCalledWith(
      expect.stringContaining('Identity migration'),
      'IDENTITY_MIGRATION',
      undefined, // no signer passed
      expect.objectContaining({
        agentDid: newDid,
        ownerDid: newDid,
      }),
    );
  });


  it('uses custom grace period when configured', async () => {
    const { pool } = createMigrationFixtures();
    const auditLogger = createMockAuditLogger();
    const executor = new MigrationExecutor({
      pool,
      agents,
      aliasRegistry: registry,
      auditLogger,
      gracePeriodDays: 14,
      migrationTrustAnchor: createTrustedAnchor(),
    });

    const result = await executor.execute(credentialJwt, makeClaims(), newDid);

    // Grace period should be ~14 days from now
    const expectedMin = Date.now() + 13 * 24 * 60 * 60 * 1000;
    const expectedMax = Date.now() + 15 * 24 * 60 * 60 * 1000;
    expect(result.gracePeriodExpiresAt.getTime()).toBeGreaterThan(expectedMin);
    expect(result.gracePeriodExpiresAt.getTime()).toBeLessThan(expectedMax);
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

    // ROLLBACK should have been called
    expect(client.query).toHaveBeenCalledWith('ROLLBACK');
    // Alias registry should NOT have been updated
    expect(registry.size).toBe(0);
    // In-memory agents should NOT have been updated
    for (const [, agent] of agents) {
      expect(agent.ownerDid).toBe(oldDid);
    }
  });

  it('rolls back and throws on agent UPDATE failure', async () => {
    const { pool } = createMigrationFixtures({ failOnStep: 'update-agents' });
    const auditLogger = createMockAuditLogger();
    const executor = new MigrationExecutor({
      pool,
      agents,
      aliasRegistry: registry,
      auditLogger,
      migrationTrustAnchor: createTrustedAnchor(),
    });

    await expect(executor.execute(credentialJwt, makeClaims(), newDid)).rejects.toThrow(
      'simulated DB error on agent UPDATE',
    );

    // In-memory state should be untouched
    expect(registry.size).toBe(0);
    for (const [, agent] of agents) {
      expect(agent.ownerDid).toBe(oldDid);
    }
  });


  it('succeeds even when audit logging fails', async () => {
    const { pool } = createMigrationFixtures();
    const auditLogger = createMockAuditLogger();
    // Make audit logger throw — migration should still succeed
    (auditLogger.logRejection as unknown as Mock).mockImplementation(() =>
      Promise.reject(new Error('audit write failed')),
    );

    const executor = new MigrationExecutor({
      pool,
      agents,
      aliasRegistry: registry,
      auditLogger,
      migrationTrustAnchor: createTrustedAnchor(),
    });

    // Should NOT throw — audit failure is best-effort.
    const result = await executor.execute(credentialJwt, makeClaims(), newDid);
    expect(result.success).toBe(true);
    expect(result.aliasCreated).toBe(true);
  });


  it('always releases the database client, even on error', async () => {
    const { pool, client } = createMigrationFixtures({ failOnStep: 'update-context' });
    const auditLogger = createMockAuditLogger();
    const executor = new MigrationExecutor({
      pool,
      agents,
      aliasRegistry: registry,
      auditLogger,
      migrationTrustAnchor: createTrustedAnchor(),
    });

    await expect(executor.execute(credentialJwt, makeClaims(), newDid)).rejects.toThrow();

    // The client must be released back to the pool
    expect(client.release).toHaveBeenCalled();
  });


  it('rolls back and leaves state unchanged on COMMIT failure', async () => {
    const { pool, client } = createMigrationFixtures({ failOnStep: 'commit' });
    const auditLogger = createMockAuditLogger();
    const executor = new MigrationExecutor({
      pool,
      agents,
      aliasRegistry: registry,
      auditLogger,
      migrationTrustAnchor: createTrustedAnchor(),
    });

    await expect(executor.execute(credentialJwt, makeClaims(), newDid)).rejects.toThrow(
      'simulated DB error on COMMIT',
    );

    expect(client.release).toHaveBeenCalled();
    // In-memory state must be untouched because the throw happens
    // before Step 4 (post-COMMIT state updates).
    expect(registry.size).toBe(0);
    for (const [, agent] of agents) {
      expect(agent.ownerDid).toBe(oldDid);
    }
  });


  it('leaves in-memory state unchanged on context UPDATE failure', async () => {
    const { pool } = createMigrationFixtures({ failOnStep: 'update-context' });
    const auditLogger = createMockAuditLogger();
    const executor = new MigrationExecutor({
      pool,
      agents,
      aliasRegistry: registry,
      auditLogger,
      migrationTrustAnchor: createTrustedAnchor(),
    });

    await expect(executor.execute(credentialJwt, makeClaims(), newDid)).rejects.toThrow(
      'simulated DB error on context UPDATE',
    );

    // Alias registry must NOT have been updated (happens after COMMIT)
    expect(registry.size).toBe(0);
    // In-memory agents must still have old owner
    for (const [, agent] of agents) {
      expect(agent.ownerDid).toBe(oldDid);
    }
  });


  it('second concurrent execute for same credential returns alreadyMigrated', async () => {
    const { pool } = createMigrationFixtures();
    const auditLogger = createMockAuditLogger();
    const executor = new MigrationExecutor({
      pool,
      agents,
      aliasRegistry: registry,
      auditLogger,
      migrationTrustAnchor: createTrustedAnchor(),
    });

    // First migration succeeds
    const result1 = await executor.execute(credentialJwt, makeClaims(), newDid);
    expect(result1.success).toBe(true);
    expect(result1.alreadyMigrated).toBe(false);

    // Second attempt with same JWT hits the in-memory idempotency check
    const result2 = await executor.execute(credentialJwt, makeClaims(), newDid);
    expect(result2.success).toBe(true);
    expect(result2.alreadyMigrated).toBe(true);
    expect(result2.agentsMigrated).toBe(0);
  });


  it('second migration for same oldDid with different credential processes in DB', async () => {
    const { pool } = createMigrationFixtures();
    const auditLogger = createMockAuditLogger();
    const executor = new MigrationExecutor({
      pool,
      agents,
      aliasRegistry: registry,
      auditLogger,
      migrationTrustAnchor: createTrustedAnchor(),
    });

    // First migration
    const result1 = await executor.execute(credentialJwt, makeClaims(), newDid);
    expect(result1.success).toBe(true);

    // Second migration with a different JWT (different hash) but same oldDid.
    // The in-memory idempotency check passes (different hash), but the DB
    // owner check should now find 0 agents under oldDid (they were "migrated").
    // The mock returns agentCount=2 regardless, so this tests the code path
    // rather than DB semantics.
    const differentJwt = makeTestJwt({ nonce: 'different' }) as TrustedMigrationCredential;
    const result2 = await executor.execute(differentJwt, makeClaims(), 'did:dht:AnotherNew');
    expect(result2.success).toBe(true);
    // addAlias overwrites on same oldDid, so size stays 1 (the second
    // alias replaced the first in-memory). This is the known overwrite
    // behavior documented in did-alias-edge-cases.test.ts.
    expect(registry.size).toBe(1);
    // The latest mapping wins
    expect(registry.didsMatch(oldDid, 'did:dht:AnotherNew')).toBe(true);
  });


  it('rejects claims with empty string previousDid', async () => {
    const { pool } = createMigrationFixtures();
    const auditLogger = createMockAuditLogger();
    const executor = new MigrationExecutor({
      pool,
      agents,
      aliasRegistry: registry,
      auditLogger,
      migrationTrustAnchor: createTrustedAnchor(),
    });

    await expect(
      executor.execute(credentialJwt, makeClaims({ previousDid: '' }), newDid),
    ).rejects.toThrow('must not be empty');
  });

  it('rejects claims with empty string oidcSubject', async () => {
    const { pool } = createMigrationFixtures();
    const auditLogger = createMockAuditLogger();
    const executor = new MigrationExecutor({
      pool,
      agents,
      aliasRegistry: registry,
      auditLogger,
      migrationTrustAnchor: createTrustedAnchor(),
    });

    await expect(
      executor.execute(credentialJwt, makeClaims({ oidcSubject: '' }), newDid),
    ).rejects.toThrow('must not be empty');
  });

  //
  // These tests cover the audit-surfaced gap: MigrationExecutor must
  // independently reject credentials whose verified issuer DID (decoded
  // from the JWT itself) is not in the build-time-baked migration trust
  // list, regardless of what the upstream LocalTrustAnchorStore accepted.
  // The trust check input comes from the JWT's `iss` claim (decoded inside
  // execute()), not from a separate caller-supplied parameter — binding the
  // check to the credential being processed.

  it('rejects migration when JWT iss is not in the migration trust anchor', async () => {
    const { pool } = createMigrationFixtures();
    const auditLogger = createMockAuditLogger();
    // Default MigrationTrustAnchor — empty (no baked issuers, no parent additions).
    const executor = new MigrationExecutor({
      pool,
      agents,
      aliasRegistry: registry,
      auditLogger,
      migrationTrustAnchor: new MigrationTrustAnchor(),
    });

    // Cast deliberately bypasses the branded type — this is the exact scenario
    // the runtime gate defends against (row 2 in the defense-in-depth table).
    const forkerJwt = makeTestJwt({ iss: 'did:dht:fork-org-issuer' }) as TrustedMigrationCredential;
    await expect(executor.execute(forkerJwt, makeClaims(), newDid)).rejects.toThrow(
      UntrustedMigrationIssuerError,
    );

    // No DB work should have occurred.
    expect(pool.connect).not.toHaveBeenCalled();
    // No alias should have been added.
    expect(registry.size).toBe(0);
    // In-memory agents map must be untouched.
    for (const [, agent] of agents) {
      expect(agent.ownerDid).toBe(oldDid);
    }
  });

  it('rejects malformed JWT (not 3 parts, invalid base64, missing iss)', async () => {
    const { pool } = createMigrationFixtures();
    const auditLogger = createMockAuditLogger();
    const executor = new MigrationExecutor({
      pool,
      agents,
      aliasRegistry: registry,
      auditLogger,
      migrationTrustAnchor: createTrustedAnchor(),
    });

    // Not 3 parts.
    await expect(
      executor.execute('not-a-jwt' as TrustedMigrationCredential, makeClaims(), newDid),
    ).rejects.toThrow(TypeError);

    // Empty middle segment.
    await expect(
      executor.execute('header..signature' as TrustedMigrationCredential, makeClaims(), newDid),
    ).rejects.toThrow(TypeError);

    // Invalid base64url payload (!! is not valid base64url).
    await expect(
      executor.execute('header.!!.signature' as TrustedMigrationCredential, makeClaims(), newDid),
    ).rejects.toThrow(TypeError);

    // Payload decodes to JSON but has no iss claim.
    const noIss =
      `header.${Buffer.from(JSON.stringify({ foo: 'bar' }), 'utf-8').toString('base64url')}.sig` as TrustedMigrationCredential;
    await expect(executor.execute(noIss, makeClaims(), newDid)).rejects.toThrow(/iss/);

    // Payload has non-string iss.
    const numIss =
      `header.${Buffer.from(JSON.stringify({ iss: 12345 }), 'utf-8').toString('base64url')}.sig` as TrustedMigrationCredential;
    await expect(executor.execute(numIss, makeClaims(), newDid)).rejects.toThrow(/iss/);

    // Payload has empty-string iss.
    const emptyIss =
      `header.${Buffer.from(JSON.stringify({ iss: '' }), 'utf-8').toString('base64url')}.sig` as TrustedMigrationCredential;
    await expect(executor.execute(emptyIss, makeClaims(), newDid)).rejects.toThrow(/iss/);

    expect(pool.connect).not.toHaveBeenCalled();
  });

  it('accepts migration when JWT iss is added via parent-credential-chain', async () => {
    const { pool } = createMigrationFixtures();
    const auditLogger = createMockAuditLogger();

    // Construct an empty trust anchor (no baked issuers) and add a runtime
    // entry the way a paid-tier consumer would after verifying a parent
    // credential. This is the only runtime path that establishes migration trust.
    const anchor = new MigrationTrustAnchor();
    anchor.addFromParentCredentialChain('did:dht:abaxxone-runtime-derived');

    const executor = new MigrationExecutor({
      pool,
      agents,
      aliasRegistry: registry,
      auditLogger,
      migrationTrustAnchor: anchor,
    });

    const trustedJwt = makeTestJwt({
      iss: 'did:dht:abaxxone-runtime-derived',
    }) as TrustedMigrationCredential;
    const result = await executor.execute(trustedJwt, makeClaims(), newDid);
    expect(result.success).toBe(true);
    expect(result.aliasCreated).toBe(true);
  });

  it('accepts JWT iss with a DID-URL fragment by normalizing it (matches bare-DID trust entry)', async () => {
    const { pool } = createMigrationFixtures();
    const auditLogger = createMockAuditLogger();
    const anchor = new MigrationTrustAnchor();
    anchor.addFromParentCredentialChain('did:dht:abaxxone-runtime');
    const executor = new MigrationExecutor({
      pool,
      agents,
      aliasRegistry: registry,
      auditLogger,
      migrationTrustAnchor: anchor,
    });

    // Verifier-produced iss often includes a key fragment (did:dht:X#key-1).
    // Trust entry stores bare DID. Normalization at lookup time must bridge them.
    const fragmentJwt = makeTestJwt({
      iss: 'did:dht:abaxxone-runtime#key-1',
    }) as TrustedMigrationCredential;
    const result = await executor.execute(fragmentJwt, makeClaims(), newDid);
    expect(result.success).toBe(true);
  });

  it('runs the trust anchor check BEFORE the idempotency check (does not leak migration history to untrusted issuers)', async () => {
    // If a previous migration succeeded for some JWT, an attacker
    // probing with a *different* JWT signed by an untrusted issuer must
    // get UntrustedMigrationIssuerError — not an alreadyMigrated:true
    // response that would let them probe whether their forged JWT happens
    // to hash-collide with a known credential. The
    // trust check is the very first gate.
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

    // Pre-seed the alias registry with the forker JWT's hash (simulates
    // an unrelated prior migration that happens to share the same JWT).
    // Spy on hasCredential so we can assert it was NEVER consulted on
    // the forker probe — the trust check must short-circuit first.
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

    // The structural assertion: idempotency check was never consulted
    // because the trust check ran first and rejected the probe.
    expect(hasCredentialSpy).not.toHaveBeenCalled();
    // No DB work either.
    expect(pool.connect).not.toHaveBeenCalled();
  });

  it('runs the trust anchor check BEFORE claim-shape validation (no schema-fingerprinting oracle)', async () => {
    // An attacker probing with malformed claims AND an untrusted issuer must
    // get UntrustedMigrationIssuerError — not the "claims must not be empty"
    // error that would let them differentiate "well-shaped claims" from
    // "untrusted issuer" responses. The trust gate is the very first gate.
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
    await expect(
      executor.execute(forkerJwt, makeClaims({ previousDid: '' }), newDid),
    ).rejects.toThrow(UntrustedMigrationIssuerError);
  });

  //
  // Demonstrates defense-in-depth: even when a caller bypasses the
  // TrustedMigrationCredential brand via `as` cast, the runtime gate
  // inside execute() still fires. Branded types are erased at compile
  // time, so the runtime check is the actual security boundary.

  it('runtime gate fires even when brand is bypassed via as-cast', async () => {
    const { pool } = createMigrationFixtures();
    const auditLogger = createMockAuditLogger();
    const executor = new MigrationExecutor({
      pool,
      agents,
      aliasRegistry: registry,
      auditLogger,
      migrationTrustAnchor: new MigrationTrustAnchor(),
    });

    const rawJwt = makeTestJwt({ iss: 'did:dht:fork-org-issuer' });
    await expect(
      executor.execute(rawJwt as TrustedMigrationCredential, makeClaims(), newDid),
    ).rejects.toThrow(UntrustedMigrationIssuerError);

    expect(pool.connect).not.toHaveBeenCalled();
  });
});
