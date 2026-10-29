import { afterEach, describe, it, expect, vi } from 'vitest';
import { ScopeEngine } from '#sql/scope-engine.js';
import * as queryPolicy from '#sql/query-policy.js';
import { VcVerifier } from '#identity/index.js';
import { InMemoryRevocationStore } from '#storage/memory/revocation-store.js';
import { AuditLogger } from '#audit/index.js';
import { generateDidKey, issueCredential } from '#auth/index.js';
import { AgentScopeError, QueryRejectedError, ScopeViolationError } from '#errors/index.js';
import type { AgentStore } from '#storage/types.js';
import type { Pool } from 'pg';
import { createMockAuditStore } from './mocks/audit-store.js';
import { createTestFixtures } from './support/scope-engine-fixtures.js';

describe('Scope Enforcement Engine', () => {
  afterEach(() => vi.restoreAllMocks());

  describe('valid queries', () => {
    it('decrypts in-scope columns for full-scope agent', async () => {
      const { human, agentA, engine } = createTestFixtures();

      const credential = await issueCredential(human.did, human.privateKey, {
        agent: agentA.did,
        columns: ['patients.name', 'patients.dob', 'patients.diagnosis'],
        actions: ['read'],
        expiresIn: '4h',
      });

      const result = await engine.query({
        agent: agentA.did,
        credential,
        table: 'patients',
        sql: 'SELECT name, dob, diagnosis FROM patients',
      });

      expect(result.rows.length).toBe(2);
      expect(result.rows[0].name).toBe('Jane Doe');
      expect(result.rows[0].dob).toBe('1990-03-15');
      expect(result.rows[0].diagnosis).toBe('Type 2 Diabetes');
    });

    it('rejects queries for encrypted columns outside scope', async () => {
      const { human, agentB, engine, pool, auditStore } = createTestFixtures();

      const credential = await issueCredential(human.did, human.privateKey, {
        agent: agentB.did,
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '4h',
      });

      const err = await engine
        .query({
          agent: agentB.did,
          credential,
          table: 'patients',
          sql: 'SELECT name, dob, diagnosis, ssn FROM patients',
        })
        .catch((err: unknown) => err);

      expect(err).toBeInstanceOf(ScopeViolationError);
      expect(err).toMatchObject({ details: { agentDid: agentB.did, auditId: expect.any(String) } });
      expect(auditStore.append).toHaveBeenCalledExactlyOnceWith(
        expect.objectContaining({
          id: (err as ScopeViolationError).details?.auditId,
          agentDid: agentB.did,
          ownerDid: human.did,
          status: 'rejected',
          reasonCode: 'SCOPE_VIOLATION',
        }),
      );
      expect(pool.query).not.toHaveBeenCalled();
    });

    it('tracks metadata correctly', async () => {
      const { human, agentA, engine } = createTestFixtures();

      const credential = await issueCredential(human.did, human.privateKey, {
        agent: agentA.did,
        columns: ['patients.name', 'patients.dob', 'patients.diagnosis'],
        actions: ['read'],
        expiresIn: '4h',
      });

      const result = await engine.query({
        agent: agentA.did,
        credential,
        table: 'patients',
        sql: 'SELECT name, dob, diagnosis FROM patients',
      });

      expect(result.metadata.agent).toBe(agentA.did);
      expect(result.metadata.owner).toBe(human.did);
      expect(result.metadata.columnsDecrypted).toContain('patients.dob');
      expect(result.metadata.columnsDecrypted).toContain('patients.diagnosis');
      expect(result.metadata.rowCount).toBe(2);
      expect(result.metadata.auditId).toBeDefined();
    });
  });

  describe.each([false, true])('rejection audit append failure=%s', (failOnAppend) => {
    it.each([
      [
        'scope violation',
        (did: string) => new ScopeViolationError(did, ['patients.ssn'], ['patients.name']),
      ],
      ['query rejection', (did: string) => new QueryRejectedError(did, 'Only SELECT is allowed')],
      ['error without details', () => new AgentScopeError('QUERY_REJECTED', 'Request rejected')],
    ] as const)(
      'preserves the original %s and correlates only a completed append',
      async (_label, createError) => {
        const { human, agentA, engine, pool, auditStore } = createTestFixtures({ failOnAppend });
        const credential = await issueCredential(human.did, human.privateKey, {
          agent: agentA.did,
          columns: ['patients.name'],
          actions: ['read'],
          expiresIn: '4h',
        });
        const originalError = createError(agentA.did);
        const originalDetails = originalError.details;
        if (originalDetails) originalDetails.auditId = 'previous-rejection-audit-id';
        const { message, code } = originalError;
        vi.spyOn(queryPolicy, 'authorizeQuery').mockRejectedValueOnce(originalError);

        await expect(
          engine.query({
            agent: agentA.did,
            credential,
            table: 'patients',
            sql: 'SELECT name FROM patients',
          }),
        ).rejects.toBe(originalError);

        expect(originalError.message).toBe(message);
        expect(originalError.code).toBe(code);
        expect(originalError.details).toBe(originalDetails);
        expect(auditStore.append).toHaveBeenCalledOnce();
        if (failOnAppend || !originalDetails) {
          expect(originalError.details?.auditId).toBeUndefined();
        } else {
          expect(originalError.details?.auditId).toEqual(expect.any(String));
          expect(originalError.details?.auditId).not.toBe('previous-rejection-audit-id');
          expect(auditStore.append).toHaveBeenCalledWith(
            expect.objectContaining({
              id: originalError.details?.auditId,
              agentDid: agentA.did,
              status: 'rejected',
              reasonCode: code,
            }),
          );
        }
        expect(pool.query).not.toHaveBeenCalled();
      },
    );
  });

  describe('credential errors', () => {
    it('rejects additional credentials without a primary before verification or execution', async () => {
      const { human, agentA, engine, verifier, pool } = createTestFixtures();
      const additionalCredential = await issueCredential(human.did, human.privateKey, {
        agent: agentA.did,
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '4h',
      });
      const verify = vi.spyOn(verifier, 'verify');

      await expect(
        engine.query({
          agent: agentA.did,
          credentials: [additionalCredential],
          table: 'patients',
          sql: 'SELECT name FROM patients',
        } as Parameters<typeof engine.query>[0]),
      ).rejects.toMatchObject({
        code: 'CREDENTIAL_MALFORMED',
        message:
          'Credential JWT missing required claim — No credential provided. Expected schema: https://abaxx.tech/schemas/agents-v1',
      });
      expect(verify).not.toHaveBeenCalled();
      expect(pool.query).not.toHaveBeenCalled();
    });

    it('rejects invalid credential signature', async () => {
      const { agentA, engine } = createTestFixtures();

      await expect(
        engine.query({
          agent: agentA.did,
          credential: 'eyJ.invalid.jwt',
          table: 'patients',
          sql: 'SELECT * FROM patients',
        }),
      ).rejects.toThrow();
    });

    it('rejects expired credential', async () => {
      const { human, agentA } = createTestFixtures();

      const credential = await issueCredential(human.did, human.privateKey, {
        agent: agentA.did,
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '1s',
      });

      // Wait for expiry (1s credential + margin)
      await new Promise((r) => setTimeout(r, 1500));

      // Use a strict verifier
      const strictVerifier = new VcVerifier({
        clockSkew: '1s',
        revocationStore: new InMemoryRevocationStore(),
      });
      const strictServer = generateDidKey();
      strictVerifier.registerKey(strictServer.did, strictServer.publicKey);
      const strictEngine = new ScopeEngine({
        pool: {} as unknown as Pool,
        verifier: strictVerifier,
        auditLogger: new AuditLogger({ auditStore: createMockAuditStore(), enabled: false }),
        columnKeys: new Map(),
        encryptedColumns: new Set(),
        agents: new Map(),
        agentStore: { findByDid: vi.fn().mockResolvedValue(null) } as unknown as AgentStore,
        verifierDid: strictServer.did,
      });

      await expect(
        strictEngine.query({
          agent: agentA.did,
          credential,
          table: 'patients',
          sql: 'SELECT * FROM patients',
        }),
      ).rejects.toThrow('expired');
    });

    it('rejects credential for wrong agent', async () => {
      const { human, agentA, agentB, engine } = createTestFixtures();

      // Issue credential to Agent A
      const credential = await issueCredential(human.did, human.privateKey, {
        agent: agentA.did,
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '4h',
      });

      // Try to use it as Agent B — VP wrapping means the subject mismatch is
      // caught when the VP (signed by Agent B) unwraps to reveal the inner VC
      // (issued to Agent A). The VP's iss becomes the expectedSubject for the VC.
      await expect(
        engine.query({
          agent: agentB.did,
          credential,
          table: 'patients',
          sql: 'SELECT * FROM patients',
        }),
      ).rejects.toThrow('subject mismatch');
    });

    it('rejects credential with missing scope', async () => {
      const { human, agentA, engine } = createTestFixtures();
      const { createJwt } = await import('#crypto/jwt.js');

      const jwt = await createJwt(
        {
          iss: human.did,
          sub: agentA.did,
          iat: Math.floor(Date.now() / 1000),
          exp: Math.floor(Date.now() / 1000) + 3600,
          vc: {
            credentialSubject: { id: agentA.did },
          },
        },
        human.privateKey,
      );

      await expect(
        engine.query({
          agent: agentA.did,
          credential: jwt,
          table: 'patients',
          sql: 'SELECT * FROM patients',
        }),
      ).rejects.toThrow();
    });
  });

  describe('multiple credentials (scope union)', () => {
    it('unions scopes from multiple valid credentials', async () => {
      const { human, agentA, engine } = createTestFixtures();

      const cred1 = await issueCredential(human.did, human.privateKey, {
        agent: agentA.did,
        columns: ['patients.name', 'patients.dob'],
        actions: ['read'],
        expiresIn: '4h',
      });

      const cred2 = await issueCredential(human.did, human.privateKey, {
        agent: agentA.did,
        columns: ['patients.diagnosis'],
        actions: ['read'],
        expiresIn: '4h',
      });

      const result = await engine.query({
        agent: agentA.did,
        credential: cred1,
        credentials: [cred2],
        table: 'patients',
        sql: 'SELECT name, dob, diagnosis FROM patients',
      });

      // Both dob and diagnosis should be decrypted via scope union
      expect(result.rows[0].dob).toBe('1990-03-15');
      expect(result.rows[0].diagnosis).toBe('Type 2 Diabetes');
    });
  });

  describe('unencrypted columns', () => {
    it('rejects unscoped unencrypted columns under projection mode', async () => {
      const { human, agentB, engine, pool } = createTestFixtures();

      const credential = await issueCredential(human.did, human.privateKey, {
        agent: agentB.did,
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '4h',
      });

      await expect(
        engine.query({
          agent: agentB.did,
          credential,
          table: 'patients',
          sql: 'SELECT id, name FROM patients',
        }),
      ).rejects.toThrow(/scope/i);
      expect(pool.query).not.toHaveBeenCalled();
    });

    it('allows unencrypted columns when explicitly in scope', async () => {
      const { human, agentB, engine } = createTestFixtures();

      const credential = await issueCredential(human.did, human.privateKey, {
        agent: agentB.did,
        columns: ['patients.id', 'patients.name'],
        actions: ['read'],
        expiresIn: '4h',
      });

      const result = await engine.query({
        agent: agentB.did,
        credential,
        table: 'patients',
        sql: 'SELECT id, name FROM patients',
      });

      expect(result.rows[0].name).toBe('Jane Doe');
      expect(result.rows[0].id).toBe(1);
    });
  });
});

describe('scopeMode validation', () => {
  function minimalEngineOpts() {
    const server = generateDidKey();
    const verifier = new VcVerifier({
      clockSkew: '30s',
      revocationStore: new InMemoryRevocationStore(),
    });
    verifier.registerKey(server.did, server.publicKey);
    const pool = { query: vi.fn() } as unknown as Pool;
    const auditLogger = new AuditLogger({ auditStore: createMockAuditStore(), enabled: false });
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

  it('accepts scopeMode=projection (explicit)', () => {
    expect(
      () => new ScopeEngine({ ...minimalEngineOpts(), scopeMode: 'projection' }),
    ).not.toThrow();
  });

  it('defaults to projection when scopeMode is omitted', () => {
    expect(() => new ScopeEngine({ ...minimalEngineOpts() })).not.toThrow();
  });

  it('rejects any non-projection value', () => {
    expect(
      () =>
        new ScopeEngine({
          ...minimalEngineOpts(),
          scopeMode: 'encryption-only' as unknown as import('../src/sql/scope-engine.js').ScopeMode,
        }),
    ).toThrow(/Invalid scopeMode/);
  });
});
