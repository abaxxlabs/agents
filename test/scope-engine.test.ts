import { afterEach, describe, it, expect, vi } from 'vitest';
import { ScopeEngine } from '#sql/scope-engine.js';
import * as queryPolicy from '#sql/query-policy.js';
import { VcVerifier } from '#identity/index.js';
import { InMemoryRevocationStore } from '#storage/memory/revocation-store.js';
import { AuditLogger } from '#audit/index.js';
import { decrypt } from '#encryption/index.js';
import { generateDidKey, issueCredential } from '#auth/index.js';
import { ScopeViolationError } from '#errors/index.js';
import type { AgentStore } from '#storage/types.js';
import type { Pool } from 'pg';
import { createMockAuditStore } from './mocks/audit-store.js';
import { createTestFixtures } from './support/scope-engine-fixtures.js';

describe('Scope Enforcement Engine', () => {
  afterEach(() => vi.restoreAllMocks());

  describe('valid queries', () => {
    it('decrypts in-scope columns and preserves out-of-scope ciphertext', async () => {
      const { human, agentA, engine, columnKeys } = createTestFixtures();

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
      expect(
        decrypt(
          Buffer.from(result.rows[0].ssn as string, 'base64'),
          columnKeys.get('patients.ssn')!,
        ),
      ).toBe('123-45-6789');
      expect(result.metadata.columnsDecrypted).toContain('patients.dob');
      expect(result.metadata.columnsDecrypted).not.toContain('patients.ssn');
      expect(result.metadata.columnsEncrypted).toContain('patients.ssn');
    });

    it('rejects out-of-scope references and preserves rejection errors when auditing fails', async () => {
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

      for (const sql of [
        "SELECT name FROM patients WHERE ssn = '123-45-6789'",
        'SELECT name FROM patients ORDER BY ssn',
        'SELECT name FROM patients GROUP BY name HAVING COUNT(id) > 1',
      ]) {
        await expect(
          engine.query({
            agent: agentB.did,
            credential,
            table: 'patients',
            sql,
          }),
        ).rejects.toBeInstanceOf(ScopeViolationError);
      }

      const originalError = err as ScopeViolationError;
      const originalDetails = originalError.details!;
      originalDetails.auditId = 'stale-rejection-audit-id';
      vi.spyOn(queryPolicy, 'authorizeQuery').mockRejectedValueOnce(originalError);
      vi.mocked(auditStore.append).mockRejectedValueOnce(new Error('disk full'));

      await expect(
        engine.query({
          agent: agentB.did,
          credential,
          table: 'patients',
          sql: 'SELECT name FROM patients',
        }),
      ).rejects.toBe(originalError);

      expect(originalError.details).toBe(originalDetails);
      expect(originalError.details).not.toHaveProperty('auditId');
      expect(auditStore.append).toHaveBeenCalledTimes(5);
      expect(pool.query).not.toHaveBeenCalled();
    });
  });

  describe('credential errors', () => {
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

      // Fake only Date: faking scheduler timers deadlocks Vitest's forks pool.
      vi.useFakeTimers({ toFake: ['Date'] });
      const issuedAt = Date.now();
      try {
        const credential = await issueCredential(human.did, human.privateKey, {
          agent: agentA.did,
          columns: ['patients.name'],
          actions: ['read'],
          expiresIn: '1s',
        });

        vi.setSystemTime(issuedAt + 1500);

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
      } finally {
        vi.useRealTimers();
      }
    });

    it('rejects credential for wrong agent', async () => {
      const { human, agentA, agentB, engine } = createTestFixtures();

      const credential = await issueCredential(human.did, human.privateKey, {
        agent: agentA.did,
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '4h',
      });

      await expect(
        engine.query({
          agent: agentB.did,
          credential,
          table: 'patients',
          sql: 'SELECT * FROM patients',
        }),
      ).rejects.toThrow('subject mismatch');
    });
  });
});
