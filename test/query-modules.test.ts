import { describe, it, expect, vi } from 'vitest';
import { QueryAuthorizer } from '#sql/authorization.js';
import { QueryRunner } from '#sql/query-execution.js';
import { ResultAssembler } from '#sql/result-assembly.js';
import { VcVerifier } from '#identity/index.js';
import { InMemoryRevocationStore } from '#storage/memory/revocation-store.js';
import { AuditLogger } from '#audit/index.js';
import { encrypt, generateColumnKey } from '#encryption/index.js';
import {
  generateDidKey,
  issueCredential,
  issueDelegatedCredential,
  createSigner,
} from '#auth/index.js';
import { CredentialInvalidError, CredentialMalformedError } from '#errors/index.js';
import type { RegisteredAgent } from '#types/index.js';
import type { AgentStore } from '#storage/types.js';
import { DidAliasRegistry } from '#did/alias.js';
import type { Pool } from 'pg';
import { createMockAuditStore } from './mocks/audit-store.js';

function createFixtures() {
  const human = generateDidKey();
  const agentA = generateDidKey();
  const agentB = generateDidKey();

  const verifier = new VcVerifier({
    clockSkew: '30s',
    revocationStore: new InMemoryRevocationStore(),
  });
  verifier.registerKey(human.did, human.publicKey);
  verifier.registerKey(agentA.did, agentA.publicKey);
  verifier.registerKey(agentB.did, agentB.publicKey);

  const agents = new Map<string, RegisteredAgent>([
    [
      agentA.did,
      {
        did: agentA.did,
        name: 'Agent A',
        ownerDid: human.did,
        signer: createSigner(agentA.privateKey),
        publicKey: agentA.publicKey,
      },
    ],
    [
      agentB.did,
      {
        did: agentB.did,
        name: 'Agent B',
        ownerDid: human.did,
        signer: createSigner(agentB.privateKey),
        publicKey: agentB.publicKey,
      },
    ],
  ]);

  const server = generateDidKey();
  verifier.registerKey(server.did, server.publicKey);

  const agentStore = {
    findByDid: vi.fn().mockResolvedValue(null),
    create: vi.fn(),
    list: vi.fn(),
    listAll: vi.fn(),
    count: vi.fn(),
  } as unknown as AgentStore;

  const authorizer = new QueryAuthorizer({
    verifier,
    agents,
    verifierDid: server.did,
    agentStore,
  });

  return { human, agentA, agentB, authorizer, agents };
}

describe('QueryAuthorizer', () => {
  it('resolves owner, read scope, and credential union for valid credentials', async () => {
    const { human, agentA, authorizer } = createFixtures();

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

    const result = await authorizer.authorize({
      agent: agentA.did,
      credential: cred1,
      credentials: [cred2],
    });

    expect(result.ownerDid).toBe(human.did);
    expect(Array.from(result.readColumns).sort()).toEqual(
      ['patients.name', 'patients.dob', 'patients.diagnosis'].sort(),
    );
    expect(result.allJwts).toEqual([cred1, cred2]);
  });

  it('rejects a missing primary credential before verification', async () => {
    const { agentA, authorizer } = createFixtures();

    await expect(
      authorizer.authorize({ agent: agentA.did, credential: '' }),
    ).rejects.toBeInstanceOf(CredentialMalformedError);
  });

  it('rejects combining delegated credentials in a union', async () => {
    const { human, agentA, agentB, authorizer } = createFixtures();

    const supervisorCred = await issueCredential(human.did, human.privateKey, {
      agent: agentA.did,
      columns: ['patients.name', 'patients.dob'],
      actions: ['read'],
      expiresIn: '4h',
    });
    const delegated = await issueDelegatedCredential(
      agentA.did,
      createSigner(agentA.privateKey),
      supervisorCred,
      'source-jti',
      { columns: ['patients.name', 'patients.dob'], actions: ['read'] },
      {
        targetAgent: agentB.did,
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '1h',
      },
    );
    const narrow = await issueCredential(human.did, human.privateKey, {
      agent: agentB.did,
      columns: ['patients.dob'],
      actions: ['read'],
      expiresIn: '4h',
    });

    await expect(
      authorizer.authorize({ agent: agentB.did, credential: delegated, credentials: [narrow] }),
    ).rejects.toMatchObject({ code: 'CREDENTIAL_INVALID' });
  });

  it('accepts a credential issued under an aliased owner DID', async () => {
    const humanOld = generateDidKey();
    const humanNew = generateDidKey();
    const agentA = generateDidKey();

    const verifier = new VcVerifier({
      clockSkew: '30s',
      revocationStore: new InMemoryRevocationStore(),
    });
    verifier.registerKey(humanOld.did, humanOld.publicKey);
    verifier.registerKey(humanNew.did, humanNew.publicKey);
    verifier.registerKey(agentA.did, agentA.publicKey);

    const server = generateDidKey();
    verifier.registerKey(server.did, server.publicKey);

    const agents = new Map<string, RegisteredAgent>([
      [
        agentA.did,
        {
          did: agentA.did,
          name: 'Agent A',
          ownerDid: humanNew.did,
          signer: createSigner(agentA.privateKey),
          publicKey: agentA.publicKey,
        },
      ],
    ]);

    const aliasRegistry = new DidAliasRegistry();
    aliasRegistry.addAlias({
      oldDid: humanOld.did,
      newDid: humanNew.did,
      credentialHash: 'test-hash',
      oidcSubject: 'user@test.com',
      oidcIssuer: 'https://login.test.com',
      migratedAt: new Date(),
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });

    const aliased = new QueryAuthorizer({
      verifier,
      agents,
      verifierDid: server.did,
      agentStore: { findByDid: vi.fn().mockResolvedValue(null) } as unknown as AgentStore,
      didAliases: aliasRegistry,
    });

    const credential = await issueCredential(humanOld.did, humanOld.privateKey, {
      agent: agentA.did,
      columns: ['patients.name'],
      actions: ['read'],
      expiresIn: '4h',
    });

    const result = await aliased.authorize({ agent: agentA.did, credential });
    expect(result.ownerDid).toBe(humanOld.did);
    expect(Array.from(result.readColumns)).toEqual(['patients.name']);
  });
});

describe('QueryRunner', () => {
  it('decrypts authorized columns and preserves unscoped encrypted values', async () => {
    const dobKey = generateColumnKey();
    const diagKey = generateColumnKey();
    const ssnKey = generateColumnKey();
    const columnKeys = new Map<string, Buffer>([
      ['patients.dob', dobKey],
      ['patients.diagnosis', diagKey],
      ['patients.ssn', ssnKey],
    ]);
    const encryptedColumns = new Set(['patients.dob', 'patients.diagnosis', 'patients.ssn']);

    const rows = [
      {
        id: 1,
        name: 'Jane Doe',
        dob: encrypt('1990-03-15', dobKey),
        diagnosis: encrypt('Type 2 Diabetes', diagKey),
        ssn: encrypt('123-45-6789', ssnKey),
      },
    ];
    const pool = {
      query: vi.fn().mockResolvedValue({ rows, rowCount: rows.length }),
    } as unknown as Pool;

    const runner = new QueryRunner({ pool, columnKeys, encryptedColumns });
    const result = await runner.execute({
      sql: 'SELECT name, dob, diagnosis, ssn FROM patients',
      table: 'patients',
      scopeColumns: ['patients.name', 'patients.dob', 'patients.diagnosis'],
    });

    expect(result.decryptedRows[0].dob).toBe('1990-03-15');
    expect(result.decryptedRows[0].diagnosis).toBe('Type 2 Diabetes');
    expect(result.decryptedRows[0].ssn).not.toBe('123-45-6789');
    expect(result.columnsDecrypted).toEqual(
      expect.arrayContaining(['patients.dob', 'patients.diagnosis']),
    );
    expect(result.columnsEncrypted).toContain('patients.ssn');
    expect(pool.query).toHaveBeenCalledWith(
      'SELECT name, dob, diagnosis, ssn FROM patients',
      undefined,
    );
  });
  it('forwards params to the database pool query', async () => {
    const colKey = generateColumnKey();
    const columnKeys = new Map<string, Buffer>([['patients.name', colKey]]);
    const encryptedColumns = new Set<string>();

    const rows = [{ name: 'Jane Doe' }];
    const pool = {
      query: vi.fn().mockResolvedValue({ rows, rowCount: rows.length }),
    } as unknown as Pool;

    const runner = new QueryRunner({ pool, columnKeys, encryptedColumns });
    const params = [42, 'Jane Doe'];
    const result = await runner.execute({
      sql: 'SELECT name FROM patients WHERE id = $1 AND name = $2',
      params,
      table: 'patients',
      scopeColumns: ['patients.name'],
    });

    expect(result.decryptedRows).toEqual([{ name: 'Jane Doe' }]);
    expect(pool.query).toHaveBeenCalledWith(
      'SELECT name FROM patients WHERE id = $1 AND name = $2',
      params,
    );
  });

  it('accumulates decrypted/encrypted columns across multiple rows', async () => {
    const dobKey = generateColumnKey();
    const ssnKey = generateColumnKey();
    const columnKeys = new Map<string, Buffer>([
      ['patients.dob', dobKey],
      ['patients.ssn', ssnKey],
    ]);
    const encryptedColumns = new Set(['patients.dob', 'patients.ssn']);

    const rows = [
      { id: 1, dob: encrypt('1990-03-15', dobKey) },
      { id: 2, ssn: encrypt('222-22-2222', ssnKey) },
    ];
    const pool = {
      query: vi.fn().mockResolvedValue({ rows, rowCount: rows.length }),
    } as unknown as Pool;

    const runner = new QueryRunner({ pool, columnKeys, encryptedColumns });
    const result = await runner.execute({
      sql: 'SELECT id, dob, ssn FROM patients ORDER BY id',
      table: 'patients',
      scopeColumns: ['patients.dob'],
    });

    expect(result.decryptedRows).toHaveLength(2);
    expect(result.decryptedRows[0].dob).toBe('1990-03-15');
    expect(result.decryptedRows[1].ssn).not.toBe('222-22-2222');
    expect(result.columnsDecrypted).toContain('patients.dob');
    expect(result.columnsEncrypted).toContain('patients.ssn');
  });
});

describe('ResultAssembler', () => {
  it('writes the audit record and assembles scoped result metadata', async () => {
    const { agentA, agents } = createFixtures();
    const auditLogger = new AuditLogger({ auditStore: createMockAuditStore(), enabled: true });

    const assembler = new ResultAssembler({ auditLogger, agents });
    const result = await assembler.assemble({
      agent: agentA.did,
      ownerDid: 'did:key:owner',
      credentialJwt: 'jwt',
      sql: 'SELECT name FROM patients',
      columnsAccessed: ['patients.name'],
      rowCount: 1,
      durationMs: 12,
      decryptedRows: [{ name: 'Jane Doe' }],
      columnsDecrypted: ['patients.name'],
      columnsEncrypted: [],
    });

    expect(result.rows).toEqual([{ name: 'Jane Doe' }]);
    expect(result.metadata.agent).toBe(agentA.did);
    expect(result.metadata.owner).toBe('did:key:owner');
    expect(result.metadata.columnsDecrypted).toEqual(['patients.name']);
    expect(result.metadata.rowCount).toBe(1);
    expect(result.metadata.queryDurationMs).toBe(12);
    expect(result.metadata.auditId).toBeDefined();
  });

  it('fails closed when the agent is not registered', async () => {
    const { agents } = createFixtures();
    const auditLogger = new AuditLogger({ auditStore: createMockAuditStore(), enabled: true });

    const assembler = new ResultAssembler({ auditLogger, agents });
    await expect(
      assembler.assemble({
        agent: 'did:key:unregistered',
        ownerDid: 'did:key:owner',
        credentialJwt: 'jwt',
        sql: 'SELECT name FROM patients',
        columnsAccessed: [],
        rowCount: 0,
        durationMs: 1,
        decryptedRows: [],
        columnsDecrypted: [],
        columnsEncrypted: [],
      }),
    ).rejects.toBeInstanceOf(CredentialInvalidError);
  });
});
