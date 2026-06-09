import { describe, it, expect, vi, beforeAll } from 'vitest';
import { ScopeEngine } from '#sql/scope-engine.js';
import { VcVerifier } from '#identity/index.js';
import { createJwt, decodeJwt } from '#crypto/jwt.js';
import { InMemoryRevocationStore } from '#storage/memory/revocation-store.js';
import { AuditLogger } from '#audit/index.js';
import type { AgentStore } from '#storage/types.js';
import { createMockAuditStore } from './mocks/audit-store.js';
import type { Pool } from 'pg';
import { encrypt, generateColumnKey } from '#encryption/index.js';
import {
  generateDidKey,
  issueCredential,
  issueDelegatedCredential,
  createSigner,
} from '#auth/index.js';
import { CredentialInvalidError, UnknownIssuerError } from '#errors/index.js';
import type { RegisteredAgent } from '#types/index.js';

function createDelegationFixtures() {
  // Human owner, supervisor agent, worker agent
  const human = generateDidKey();
  const supervisor = generateDidKey();
  const worker = generateDidKey();

  const verifier = new VcVerifier({
    clockSkew: '30s',
    revocationStore: new InMemoryRevocationStore(),
  });
  verifier.registerKey(human.did, human.publicKey);
  verifier.registerKey(supervisor.did, supervisor.publicKey);
  verifier.registerKey(worker.did, worker.publicKey);

  const dobKey = generateColumnKey();
  const diagKey = generateColumnKey();
  const columnKeys = new Map<string, Buffer>([
    ['patients.dob', dobKey],
    ['patients.diagnosis', diagKey],
  ]);
  const encryptedColumns = new Set(['patients.dob', 'patients.diagnosis']);

  const sampleRows = [
    {
      id: 1,
      name: 'Jane Doe',
      dob: encrypt('1990-03-15', dobKey),
      diagnosis: encrypt('Type 2 Diabetes', diagKey),
    },
  ];

  const pool = {
    query: vi.fn().mockImplementation(async (sql: string) => {
      if (sql.includes('INSERT INTO agent_audit')) {
        return { rows: [], rowCount: 1 };
      }
      if (sql.includes('SELECT') && sql.includes('patients')) {
        return { rows: sampleRows, rowCount: sampleRows.length };
      }
      return { rows: [], rowCount: 0 };
    }),
  } as unknown as Pool;

  const agents = new Map<string, RegisteredAgent>([
    [
      supervisor.did,
      {
        did: supervisor.did,
        name: 'Supervisor',
        ownerDid: human.did,
        signer: createSigner(supervisor.privateKey),
        publicKey: supervisor.publicKey,
      },
    ],
    [
      worker.did,
      {
        did: worker.did,
        name: 'Worker',
        ownerDid: human.did,
        signer: createSigner(worker.privateKey),
        publicKey: worker.publicKey,
      },
    ],
  ]);

  const server = generateDidKey();
  verifier.registerKey(server.did, server.publicKey);

  const auditLogger = new AuditLogger({
    auditStore: createMockAuditStore(),
    enabled: true,
  });

  const engine = new ScopeEngine({
    pool,
    verifier,
    auditLogger,
    columnKeys,
    encryptedColumns,
    agents,
    verifierDid: server.did,
    agentStore: { findByDid: vi.fn().mockResolvedValue(null) } as unknown as AgentStore,
  });

  return { human, supervisor, worker, engine, verifier, pool, agents };
}

describe('Delegation', () => {
  describe('valid delegation chain', () => {
    it('accepts a delegated credential with a valid chain back to the human owner', async () => {
      const { human, supervisor, worker, engine } = createDelegationFixtures();

      // Human issues credential to supervisor
      const supervisorCred = await issueCredential(human.did, human.privateKey, {
        agent: supervisor.did,
        columns: ['patients.name', 'patients.dob', 'patients.diagnosis'],
        actions: ['read'],
        expiresIn: '4h',
      });

      // Supervisor delegates a subset to worker
      const delegatedCred = await issueDelegatedCredential(
        supervisor.did,
        createSigner(supervisor.privateKey),
        supervisorCred,
        'source-jti',
        { columns: ['patients.name', 'patients.dob', 'patients.diagnosis'], actions: ['read'] },
        {
          targetAgent: worker.did,
          columns: ['patients.name', 'patients.dob'],
          actions: ['read'],
          expiresIn: '1h',
        },
      );

      // Worker queries with the delegated credential
      const result = await engine.query({
        agent: worker.did,
        credential: delegatedCred,
        table: 'patients',
        sql: 'SELECT name, dob FROM patients',
      });

      expect(result.rows.length).toBe(1);
      expect(result.rows[0].name).toBe('Jane Doe');
      expect(result.rows[0].dob).toBe('1990-03-15');
    });
  });

  describe('invalid delegation chain', () => {
    it('rejects a delegated credential when the source credential is forged', async () => {
      const { supervisor, worker, engine } = createDelegationFixtures();

      // Attacker forges a source credential (signed by an unknown key)
      const attacker = generateDidKey();
      const forgedSourceCred = await issueCredential(attacker.did, attacker.privateKey, {
        agent: supervisor.did,
        columns: ['patients.name', 'patients.dob', 'patients.diagnosis'],
        actions: ['read'],
        expiresIn: '4h',
      });

      const delegatedCred = await issueDelegatedCredential(
        supervisor.did,
        createSigner(supervisor.privateKey),
        forgedSourceCred,
        'forged-jti',
        { columns: ['patients.name', 'patients.dob'], actions: ['read'] },
        {
          targetAgent: worker.did,
          columns: ['patients.name'],
          actions: ['read'],
          expiresIn: '1h',
        },
      );

      await expect(
        engine.query({
          agent: worker.did,
          credential: delegatedCred,
          table: 'patients',
          sql: 'SELECT name FROM patients',
        }),
      ).rejects.toThrow(UnknownIssuerError);
    });

    it('rejects a delegated credential when the source credential issuer is not the human owner', async () => {
      const { supervisor, worker, engine, verifier } = createDelegationFixtures();

      // Different human — not the owner of supervisor
      const otherHuman = generateDidKey();
      verifier.registerKey(otherHuman.did, otherHuman.publicKey);

      const sourceCred = await issueCredential(otherHuman.did, otherHuman.privateKey, {
        agent: supervisor.did,
        columns: ['patients.name', 'patients.dob'],
        actions: ['read'],
        expiresIn: '4h',
      });

      const delegatedCred = await issueDelegatedCredential(
        supervisor.did,
        createSigner(supervisor.privateKey),
        sourceCred,
        'other-jti',
        { columns: ['patients.name'], actions: ['read'] },
        {
          targetAgent: worker.did,
          columns: ['patients.name'],
          actions: ['read'],
          expiresIn: '1h',
        },
      );

      await expect(
        engine.query({
          agent: worker.did,
          credential: delegatedCred,
          table: 'patients',
          sql: 'SELECT name FROM patients',
        }),
      ).rejects.toThrow(CredentialInvalidError);
    });

    it('rejects a non-delegated credential from an agent (not the human owner)', async () => {
      const { supervisor, worker, engine } = createDelegationFixtures();

      // Supervisor issues a regular (non-delegated) credential directly —
      // but the C1 check requires issuer == human owner
      const directCred = await issueCredential(supervisor.did, supervisor.privateKey, {
        agent: worker.did,
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '1h',
      });

      await expect(
        engine.query({
          agent: worker.did,
          credential: directCred,
          table: 'patients',
          sql: 'SELECT name FROM patients',
        }),
      ).rejects.toThrow(CredentialInvalidError);
    });
  });

  describe('delegated credential scope union rejection', () => {
    it('rejects a query when a worker presents two narrow delegated credentials from the same supervisor', async () => {
      const { human, supervisor, worker, engine } = createDelegationFixtures();

      const supervisorCred = await issueCredential(human.did, human.privateKey, {
        agent: supervisor.did,
        columns: ['patients.name', 'patients.dob', 'patients.diagnosis'],
        actions: ['read'],
        expiresIn: '4h',
      });

      const credA = await issueDelegatedCredential(
        supervisor.did,
        createSigner(supervisor.privateKey),
        supervisorCred,
        'source-jti-a',
        { columns: ['patients.name', 'patients.dob', 'patients.diagnosis'], actions: ['read'] },
        {
          targetAgent: worker.did,
          columns: ['patients.name'],
          actions: ['read'],
          expiresIn: '1h',
        },
      );

      const credB = await issueDelegatedCredential(
        supervisor.did,
        createSigner(supervisor.privateKey),
        supervisorCred,
        'source-jti-b',
        { columns: ['patients.name', 'patients.dob', 'patients.diagnosis'], actions: ['read'] },
        {
          targetAgent: worker.did,
          columns: ['patients.dob', 'patients.diagnosis'],
          actions: ['read'],
          expiresIn: '1h',
        },
      );

      await expect(
        engine.query({
          agent: worker.did,
          credential: credA,
          credentials: [credB],
          table: 'patients',
          sql: 'SELECT name, dob, diagnosis FROM patients',
        }),
      ).rejects.toThrow(CredentialInvalidError);
    });

    it('accepts a single delegated credential covering the full authorized scope', async () => {
      const { human, supervisor, worker, engine } = createDelegationFixtures();

      const supervisorCred = await issueCredential(human.did, human.privateKey, {
        agent: supervisor.did,
        columns: ['patients.name', 'patients.dob', 'patients.diagnosis'],
        actions: ['read'],
        expiresIn: '4h',
      });

      const credFull = await issueDelegatedCredential(
        supervisor.did,
        createSigner(supervisor.privateKey),
        supervisorCred,
        'source-jti-full',
        { columns: ['patients.name', 'patients.dob', 'patients.diagnosis'], actions: ['read'] },
        {
          targetAgent: worker.did,
          columns: ['patients.name', 'patients.dob'],
          actions: ['read'],
          expiresIn: '1h',
        },
      );

      const result = await engine.query({
        agent: worker.did,
        credential: credFull,
        table: 'patients',
        sql: 'SELECT name, dob FROM patients',
      });

      expect(result.rows.length).toBe(1);
      expect(result.rows[0].name).toBe('Jane Doe');
      expect(result.rows[0].dob).toBe('1990-03-15');
    });
  });

  describe('delegation depth constraints', () => {
    const human = generateDidKey();
    const supervisor = generateDidKey();
    const worker = generateDidKey();

    let hop1: string;

    beforeAll(async () => {
      hop1 = await issueCredential(human.did, human.privateKey, {
        agent: supervisor.did,
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '4h',
      });
    });

    it('allows single-hop delegation (human to supervisor to worker)', async () => {
      const decoded = decodeJwt(hop1);
      const delegated = await issueDelegatedCredential(
        supervisor.did,
        createSigner(supervisor.privateKey),
        hop1,
        decoded.payload.jti!,
        { columns: ['patients.name'], actions: ['read'] },
        { targetAgent: worker.did, columns: ['patients.name'], actions: ['read'], expiresIn: '2h' },
      );
      expect(typeof delegated).toBe('string');
      expect(delegated.split('.').length).toBe(3);
    });

    it('rejects empty delegationChain at issuance', async () => {
      const now = Math.floor(Date.now() / 1000);
      const craftedJwt = await createJwt(
        {
          iss: human.did,
          sub: supervisor.did,
          jti: 'crafted-empty-chain',
          iat: now,
          exp: now + 3600,
          delegationChain: [],
          vc: {
            '@context': ['https://www.w3.org/2018/credentials/v1'],
            type: ['VerifiableCredential', 'AgentScopeCredential'],
            credentialSubject: {
              id: supervisor.did,
              scope: { columns: ['patients.name'], actions: ['read'] },
            },
          },
        },
        human.privateKey,
      );

      await expect(
        issueDelegatedCredential(
          supervisor.did,
          createSigner(supervisor.privateKey),
          craftedJwt,
          'crafted-empty-chain',
          { columns: ['patients.name'], actions: ['read'] },
          {
            targetAgent: worker.did,
            columns: ['patients.name'],
            actions: ['read'],
            expiresIn: '1h',
          },
        ),
      ).rejects.toThrow(/empty delegationChain/);
    });

    it('rejects empty delegationChain at verification', async () => {
      const verifier = new VcVerifier({ revocationStore: new InMemoryRevocationStore() });
      const now = Math.floor(Date.now() / 1000);
      const craftedJwt = await createJwt(
        {
          iss: human.did,
          sub: supervisor.did,
          jti: 'crafted-empty-chain-verify',
          iat: now,
          exp: now + 3600,
          delegationChain: [],
          vc: {
            '@context': ['https://www.w3.org/2018/credentials/v1'],
            type: ['VerifiableCredential', 'AgentScopeCredential'],
            credentialSubject: {
              id: supervisor.did,
              scope: { columns: ['patients.name'], actions: ['read'] },
            },
          },
        },
        human.privateKey,
      );

      const result = await verifier.verify(craftedJwt);
      expect(result.valid).toBe(false);
      expect(result.status).toBe('MALFORMED');
      expect(result.error).toMatch(/empty delegationChain/);
    });
  });
});
