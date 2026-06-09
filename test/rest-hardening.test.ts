import { describe, it, expect, vi } from 'vitest';
import { ScopeEngine } from '#sql/scope-engine.js';
import { VcVerifier } from '#identity/index.js';
import { InMemoryRevocationStore } from '#storage/memory/revocation-store.js';
import { AuditLogger, hashAuditRecord } from '#audit/index.js';
import { encrypt, generateColumnKey } from '#encryption/index.js';
import { generateDidKey, issueCredential, createSigner } from '#auth/index.js';
import { ScopeViolationError, CapabilityRequiresPaidTierError } from '#errors/index.js';
import type { RegisteredAgent } from '#types/index.js';
import type { AgentStore } from '#storage/types.js';
import type { Pool } from 'pg';
import { createMockAuditStore } from './mocks/audit-store.js';


function createTestFixtures() {
  const human = generateDidKey();
  const agentA = generateDidKey();
  const server = generateDidKey();

  const verifier = new VcVerifier({
    clockSkew: '30s',
    revocationStore: new InMemoryRevocationStore(),
  });
  verifier.registerKey(human.did, human.publicKey);
  verifier.registerKey(agentA.did, agentA.publicKey);
  verifier.registerKey(server.did, server.publicKey);

  const dobKey = generateColumnKey();
  const diagKey = generateColumnKey();
  const ssnKey = generateColumnKey();
  const columnKeys = new Map<string, Buffer>([
    ['patients.dob', dobKey],
    ['patients.diagnosis', diagKey],
    ['patients.ssn', ssnKey],
  ]);

  const encryptedColumns = new Set(['patients.dob', 'patients.diagnosis', 'patients.ssn']);

  const sampleRows = [
    {
      id: 1,
      name: 'Jane Doe',
      dob: encrypt('1990-03-15', dobKey),
      diagnosis: encrypt('Type 2 Diabetes', diagKey),
      ssn: encrypt('123-45-6789', ssnKey),
    },
  ];

  const pool = {
    query: vi.fn().mockImplementation(async (sql: string) => {
      if (sql.includes('INSERT INTO agent_audit')) return { rows: [], rowCount: 1 };
      if (sql.includes('SELECT') && sql.includes('patients'))
        return { rows: sampleRows, rowCount: 1 };
      return { rows: [], rowCount: 0 };
    }),
  } as unknown as Pool;

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
  ]);

  const auditStore = createMockAuditStore();
  const auditLogger = new AuditLogger({ auditStore, enabled: true });

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

  return { human, agentA, engine, pool, auditLogger };
}


describe('Projection Boundary', () => {
  it('rejects SELECT * when encrypted columns are out of scope', async () => {
    const { human, agentA, engine } = createTestFixtures();

    const credential = await issueCredential(human.did, human.privateKey, {
      agent: agentA.did,
      columns: ['patients.dob'],
      actions: ['read'],
      expiresIn: '4h',
    });

    await expect(
      engine.query({
        agent: agentA.did,
        credential,
        table: 'patients',
        sql: 'SELECT * FROM patients',
      }),
    ).rejects.toThrow(ScopeViolationError);
  });

  it('allows explicit column list when all columns are in scope', async () => {
    const { human, agentA, engine } = createTestFixtures();

    const credential = await issueCredential(human.did, human.privateKey, {
      agent: agentA.did,
      columns: [
        'patients.id',
        'patients.name',
        'patients.dob',
        'patients.diagnosis',
        'patients.ssn',
      ],
      actions: ['read'],
      expiresIn: '4h',
    });

    const result = await engine.query({
      agent: agentA.did,
      credential,
      table: 'patients',
      sql: 'SELECT id, name, dob, diagnosis, ssn FROM patients',
    });

    expect(result.rows.length).toBe(1);
  });

  it('rejects aliased out-of-scope encrypted columns', async () => {
    const { human, agentA, engine } = createTestFixtures();

    const credential = await issueCredential(human.did, human.privateKey, {
      agent: agentA.did,
      columns: ['patients.dob'],
      actions: ['read'],
      expiresIn: '4h',
    });

    await expect(
      engine.query({
        agent: agentA.did,
        credential,
        table: 'patients',
        sql: 'SELECT dob, ssn AS social FROM patients',
      }),
    ).rejects.toThrow(ScopeViolationError);
  });

  it('rejects out-of-scope encrypted column in WHERE clause (oracle prevention)', async () => {
    const { human, agentA, engine } = createTestFixtures();

    const credential = await issueCredential(human.did, human.privateKey, {
      agent: agentA.did,
      columns: ['patients.dob'],
      actions: ['read'],
      expiresIn: '4h',
    });

    await expect(
      engine.query({
        agent: agentA.did,
        credential,
        table: 'patients',
        sql: "SELECT dob FROM patients WHERE ssn = '123-45-6789'",
      }),
    ).rejects.toThrow(ScopeViolationError);
  });

  it('rejects out-of-scope encrypted column in ORDER BY', async () => {
    const { human, agentA, engine } = createTestFixtures();

    const credential = await issueCredential(human.did, human.privateKey, {
      agent: agentA.did,
      columns: ['patients.dob'],
      actions: ['read'],
      expiresIn: '4h',
    });

    await expect(
      engine.query({
        agent: agentA.did,
        credential,
        table: 'patients',
        sql: 'SELECT dob FROM patients ORDER BY ssn',
      }),
    ).rejects.toThrow(ScopeViolationError);
  });

  it('allows in-scope columns in WHERE and ORDER BY', async () => {
    const { human, agentA, engine } = createTestFixtures();

    const credential = await issueCredential(human.did, human.privateKey, {
      agent: agentA.did,
      columns: ['patients.id', 'patients.name', 'patients.dob'],
      actions: ['read'],
      expiresIn: '4h',
    });

    const result = await engine.query({
      agent: agentA.did,
      credential,
      table: 'patients',
      sql: "SELECT dob FROM patients WHERE name = 'Jane Doe' ORDER BY id",
    });

    expect(result.rows.length).toBe(1);
  });

  it('allows in-scope encrypted columns in WHERE clause', async () => {
    const { human, agentA, engine } = createTestFixtures();

    const credential = await issueCredential(human.did, human.privateKey, {
      agent: agentA.did,
      columns: ['patients.dob', 'patients.diagnosis'],
      actions: ['read'],
      expiresIn: '4h',
    });

    const result = await engine.query({
      agent: agentA.did,
      credential,
      table: 'patients',
      sql: "SELECT dob FROM patients WHERE diagnosis = 'test'",
    });

    expect(result.rows.length).toBe(1);
  });
});


describe('Projection Mode (scopeMode=projection)', () => {
  function createProjectionFixtures() {
    const human = generateDidKey();
    const agentA = generateDidKey();
    const server = generateDidKey();
    const verifier = new VcVerifier({
      clockSkew: '30s',
      revocationStore: new InMemoryRevocationStore(),
    });
    verifier.registerKey(human.did, human.publicKey);
    verifier.registerKey(agentA.did, agentA.publicKey);
    verifier.registerKey(server.did, server.publicKey);

    const dobKey = generateColumnKey();
    const columnKeys = new Map([['patients.dob', dobKey]]);
    const encryptedColumns = new Set(['patients.dob']);

    const sampleRows = [{ id: 1, name: 'Jane', dob: encrypt('1990-03-15', dobKey) }];
    const pool = {
      query: vi.fn().mockImplementation(async (sql: string) => {
        if (sql.includes('INSERT INTO agent_audit')) return { rows: [], rowCount: 1 };
        return { rows: sampleRows, rowCount: 1 };
      }),
    } as unknown as Pool;

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
    ]);

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
      scopeMode: 'projection',
      agentStore: { findByDid: vi.fn().mockResolvedValue(null) } as unknown as AgentStore,
    });

    return { human, agentA, engine };
  }

  it('rejects SELECT * unconditionally (schema unknown)', async () => {
    const { human, agentA, engine } = createProjectionFixtures();

    const credential = await issueCredential(human.did, human.privateKey, {
      agent: agentA.did,
      columns: ['patients.dob'],
      actions: ['read'],
      expiresIn: '4h',
    });

    await expect(
      engine.query({
        agent: agentA.did,
        credential,
        table: 'patients',
        sql: 'SELECT * FROM patients',
      }),
    ).rejects.toThrow(ScopeViolationError);
  });

  it('rejects unencrypted columns not in scope', async () => {
    const { human, agentA, engine } = createProjectionFixtures();

    const credential = await issueCredential(human.did, human.privateKey, {
      agent: agentA.did,
      columns: ['patients.dob'],
      actions: ['read'],
      expiresIn: '4h',
    });

    await expect(
      engine.query({
        agent: agentA.did,
        credential,
        table: 'patients',
        sql: "SELECT dob FROM patients WHERE name = 'Jane'",
      }),
    ).rejects.toThrow(ScopeViolationError);
  });

  it('allows query when all referenced columns are in scope', async () => {
    const { human, agentA, engine } = createProjectionFixtures();

    const credential = await issueCredential(human.did, human.privateKey, {
      agent: agentA.did,
      columns: ['patients.dob', 'patients.name', 'patients.id'],
      actions: ['read'],
      expiresIn: '4h',
    });

    const result = await engine.query({
      agent: agentA.did,
      credential,
      table: 'patients',
      sql: "SELECT dob FROM patients WHERE name = 'Jane'",
    });

    expect(result.rows.length).toBe(1);
  });

  it('allows table-qualified column references when in scope', async () => {
    const { human, agentA, engine } = createProjectionFixtures();

    const credential = await issueCredential(human.did, human.privateKey, {
      agent: agentA.did,
      columns: ['patients.dob', 'patients.name', 'patients.id'],
      actions: ['read'],
      expiresIn: '4h',
    });

    const result = await engine.query({
      agent: agentA.did,
      credential,
      table: 'patients',
      sql: 'SELECT patients.dob, patients.name FROM patients WHERE patients.id = 1',
    });

    expect(result.rows.length).toBe(1);
  });

  it('rejects table-qualified column not in scope', async () => {
    const { human, agentA, engine } = createProjectionFixtures();

    const credential = await issueCredential(human.did, human.privateKey, {
      agent: agentA.did,
      columns: ['patients.dob'],
      actions: ['read'],
      expiresIn: '4h',
    });

    await expect(
      engine.query({
        agent: agentA.did,
        credential,
        table: 'patients',
        sql: 'SELECT patients.name FROM patients',
      }),
    ).rejects.toThrow(ScopeViolationError);
  });

  it('rejects unencrypted out-of-scope column in ORDER BY', async () => {
    const { human, agentA, engine } = createProjectionFixtures();

    const credential = await issueCredential(human.did, human.privateKey, {
      agent: agentA.did,
      columns: ['patients.dob'],
      actions: ['read'],
      expiresIn: '4h',
    });

    await expect(
      engine.query({
        agent: agentA.did,
        credential,
        table: 'patients',
        sql: 'SELECT dob FROM patients ORDER BY name',
      }),
    ).rejects.toThrow(ScopeViolationError);
  });
});


describe('ScopeViolationError.toSafeResponse', () => {
  it('strips column names from the response', () => {
    const err = new ScopeViolationError(
      'did:key:test',
      ['patients.ssn', 'patients.diagnosis'],
      ['patients.name'],
    );

    const safe = err.toSafeResponse();

    expect(safe.code).toBe('SCOPE_VIOLATION');
    expect(safe.message).not.toContain('ssn');
    expect(safe.message).not.toContain('diagnosis');
    expect(safe.message).not.toContain('name');
  });

  it('preserves requestedColumns and authorizedColumns on the error instance', () => {
    const err = new ScopeViolationError(
      'did:key:test',
      ['patients.ssn'],
      ['patients.name', 'patients.dob'],
    );

    expect(err.requestedColumns).toEqual(['patients.ssn']);
    expect(err.authorizedColumns).toEqual(['patients.name', 'patients.dob']);
  });
});


describe('AuditLogger.logRejection', () => {
  it('creates a V3 rejection record with status and reason', async () => {
    const logger = new AuditLogger({
      auditStore: createMockAuditStore(),
      enabled: true,
    });
    const agent = generateDidKey();

    const record = await logger.logRejection(
      'Scope violation: queried unauthorized columns',
      'SCOPE_VIOLATION',
      createSigner(agent.privateKey),
      { agentDid: agent.did, ownerDid: 'did:key:owner', sql: 'SELECT ssn FROM patients' },
    );

    expect(record.version).toBe(3);
    expect(record.status).toBe('rejected');
    expect(record.reason).toBe('Scope violation: queried unauthorized columns');
    expect(record.reasonCode).toBe('SCOPE_VIOLATION');
    expect(record.agentDid).toBe(agent.did);
    expect(record.signature).toBeDefined();
    expect(record.signature.split('.').length).toBe(3);
  });

  it('creates unsigned record when no signer provided', async () => {
    const logger = new AuditLogger({
      auditStore: createMockAuditStore(),
      enabled: true,
    });

    const record = await logger.logRejection('SQL parse error', 'QUERY_REJECTED');

    expect(record.signature).toBe('unsigned');
    expect(record.agentDid).toBe('unknown');
    expect(record.status).toBe('rejected');
  });

  it('chains rejection records into the hash chain', async () => {
    const logger = new AuditLogger({
      auditStore: createMockAuditStore(),
      enabled: true,
    });

    const record1 = await logger.logRejection('first', 'TEST');
    const record2 = await logger.logRejection('second', 'TEST');

    expect(record1.previousHash).toBe('GENESIS');
    expect(record2.previousHash).not.toBe('GENESIS');

    const expectedHash = hashAuditRecord({
      id: record1.id,
      timestamp: record1.timestamp,
      agentDid: record1.agentDid,
      ownerDid: record1.ownerDid,
      credentialId: record1.credentialId,
      queryHash: record1.queryHash,
      columnsAccessed: record1.columnsAccessed,
      rowCount: record1.rowCount,
      durationMs: record1.durationMs,
      previousHash: record1.previousHash,
      version: record1.version,
      status: record1.status,
      reason: record1.reason,
      reasonCode: record1.reasonCode,
    });
    expect(record2.previousHash).toBe(expectedHash);
  });

  it('throws on rejection write failure (always fail-closed)', async () => {
    const failStore = createMockAuditStore({ failOnAppend: true });

    const logger = new AuditLogger({ auditStore: failStore, enabled: true });
    await expect(logger.logRejection('test', 'TEST')).rejects.toThrow(
      'Could not write audit record',
    );
  });

  it('interleaves with success records in the hash chain', async () => {
    const logger = new AuditLogger({
      auditStore: createMockAuditStore(),
      enabled: true,
    });
    const agent = generateDidKey();
    const signer = createSigner(agent.privateKey);
    const entry = {
      agentDid: agent.did,
      ownerDid: 'did:key:owner',
      credentialJwt: 'eyJ...',
      sql: 'SELECT name FROM patients',
      columnsAccessed: ['patients.name'],
      rowCount: 1,
      durationMs: 10,
    };

    const r1 = await logger.log(entry, signer);
    const r2 = await logger.logRejection('denied', 'SCOPE_VIOLATION');
    const r3 = await logger.log(entry, signer);

    expect(r1.previousHash).toBe('GENESIS');
    expect(r2.previousHash).not.toBe('GENESIS');
    expect(r3.previousHash).not.toBe(r2.previousHash);
    expect(r1.status).toBe('success');
    expect(r2.status).toBe('rejected');
    expect(r3.status).toBe('success');
  });
});


describe('Fail-closed DB error on agent lookup', () => {
  it('throws CredentialInvalidError when agent DB lookup fails', async () => {
    const human = generateDidKey();
    const agentA = generateDidKey();
    const server = generateDidKey();

    const verifier = new VcVerifier({
      clockSkew: '30s',
      revocationStore: new InMemoryRevocationStore(),
    });
    verifier.registerKey(human.did, human.publicKey);
    verifier.registerKey(server.did, server.publicKey);

    const failPool = {
      query: vi.fn().mockImplementation(async (sql: string) => {
        if (sql.includes('agents')) throw new Error('connection refused');
        if (sql.includes('INSERT INTO agent_audit')) return { rows: [], rowCount: 1 };
        if (sql.includes('patients')) return { rows: [{ id: 1, name: 'test' }], rowCount: 1 };
        return { rows: [], rowCount: 0 };
      }),
    } as unknown as Pool;

    const engine = new ScopeEngine({
      pool: failPool,
      verifier,
      auditLogger: new AuditLogger({
        auditStore: createMockAuditStore(),
        enabled: true,
      }),
      columnKeys: new Map(),
      encryptedColumns: new Set(),
      agents: new Map(),
      verifierDid: server.did,
      agentStore: {
        findByDid: vi.fn().mockRejectedValue(new Error('connection refused')),
      } as unknown as AgentStore,
    });

    const credential = await issueCredential(human.did, human.privateKey, {
      agent: agentA.did,
      columns: ['patients.name'],
      actions: ['read'],
      expiresIn: '4h',
    });

    await expect(
      engine.query({
        agent: agentA.did,
        credential,
        table: 'patients',
        sql: 'SELECT name FROM patients',
      }),
    ).rejects.toThrow('Agent owner lookup failed');
  });
});


describe('parseDurationSimple via issueCredential', () => {
  it('accepts integer seconds', async () => {
    const human = generateDidKey();
    const agent = generateDidKey();
    const jwt = await issueCredential(human.did, human.privateKey, {
      agent: agent.did,
      columns: ['col.a'],
      actions: ['read'],
      expiresIn: 3600,
    });
    expect(jwt.split('.').length).toBe(3);
  });

  it('rejects zero seconds', async () => {
    const human = generateDidKey();
    const agent = generateDidKey();
    await expect(
      issueCredential(human.did, human.privateKey, {
        agent: agent.did,
        columns: ['col.a'],
        actions: ['read'],
        expiresIn: 0,
      }),
    ).rejects.toThrow('positive integer');
  });

  it('rejects negative seconds', async () => {
    const human = generateDidKey();
    const agent = generateDidKey();
    await expect(
      issueCredential(human.did, human.privateKey, {
        agent: agent.did,
        columns: ['col.a'],
        actions: ['read'],
        expiresIn: -100,
      }),
    ).rejects.toThrow('positive integer');
  });

  it('rejects NaN', async () => {
    const human = generateDidKey();
    const agent = generateDidKey();
    await expect(
      issueCredential(human.did, human.privateKey, {
        agent: agent.did,
        columns: ['col.a'],
        actions: ['read'],
        expiresIn: NaN,
      }),
    ).rejects.toThrow('positive integer');
  });

  it('rejects Infinity', async () => {
    const human = generateDidKey();
    const agent = generateDidKey();
    await expect(
      issueCredential(human.did, human.privateKey, {
        agent: agent.did,
        columns: ['col.a'],
        actions: ['read'],
        expiresIn: Infinity,
      }),
    ).rejects.toThrow('positive integer');
  });

  it('rejects non-integer floats', async () => {
    const human = generateDidKey();
    const agent = generateDidKey();
    await expect(
      issueCredential(human.did, human.privateKey, {
        agent: agent.did,
        columns: ['col.a'],
        actions: ['read'],
        expiresIn: 3.5,
      }),
    ).rejects.toThrow('positive integer');
  });

  it('rejects "0s" string duration', async () => {
    const human = generateDidKey();
    const agent = generateDidKey();
    await expect(
      issueCredential(human.did, human.privateKey, {
        agent: agent.did,
        columns: ['col.a'],
        actions: ['read'],
        expiresIn: '0s',
      }),
    ).rejects.toThrow('Duration must be positive');
  });

  it('rejects "0h" string duration', async () => {
    const human = generateDidKey();
    const agent = generateDidKey();
    await expect(
      issueCredential(human.did, human.privateKey, {
        agent: agent.did,
        columns: ['col.a'],
        actions: ['read'],
        expiresIn: '0h',
      }),
    ).rejects.toThrow('Duration must be positive');
  });
});


describe('CapabilityRequiresPaidTierError', () => {
  it('includes capability, namespace, and signup URL', () => {
    const err = new CapabilityRequiresPaidTierError('vc:issue', 'vc');
    expect(err.code).toBe('CAPABILITY_REQUIRES_PAID_TIER');
    expect(err.capability).toBe('vc:issue');
    expect(err.namespace).toBe('vc');
    expect(err.message).toContain('vc:issue');
    expect(err.message).toContain('AbaxxOne');
    expect(err.details?.signupUrl).toBe('https://abaxx.tech/one');
  });

  it('is an instance of AgentScopeError', () => {
    const err = new CapabilityRequiresPaidTierError('scope:admin', 'scope');
    expect(err).toBeInstanceOf(CapabilityRequiresPaidTierError);
    expect(err.name).toBe('CapabilityRequiresPaidTierError');
  });

  it('includes capability and namespace in details object', () => {
    const err = new CapabilityRequiresPaidTierError('vc:issue', 'vc');
    expect(err.details?.capability).toBe('vc:issue');
    expect(err.details?.namespace).toBe('vc');
  });
});


describe('Projection mode defaults and edge cases', () => {
  it('defaults to projection mode when scopeMode is omitted', async () => {
    const human = generateDidKey();
    const agentA = generateDidKey();
    const server = generateDidKey();

    const verifier = new VcVerifier({
      clockSkew: '30s',
      revocationStore: new InMemoryRevocationStore(),
    });
    verifier.registerKey(human.did, human.publicKey);
    verifier.registerKey(agentA.did, agentA.publicKey);
    verifier.registerKey(server.did, server.publicKey);

    const dobKey = generateColumnKey();
    const columnKeys = new Map<string, Buffer>([['patients.dob', dobKey]]);
    const encryptedColumns = new Set(['patients.dob']);
    const pool = {
      query: vi.fn().mockImplementation(async () => ({ rows: [], rowCount: 0 })),
    } as unknown as Pool;
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
    ]);
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
      // scopeMode intentionally omitted — should default to 'projection'
      agentStore: { findByDid: vi.fn().mockResolvedValue(null) } as unknown as AgentStore,
    });

    const credential = await issueCredential(human.did, human.privateKey, {
      agent: agentA.did,
      columns: ['patients.dob'],
      actions: ['read'],
      expiresIn: '4h',
    });

    // Unencrypted column 'name' not in scope — should throw in projection mode
    await expect(
      engine.query({
        agent: agentA.did,
        credential,
        table: 'patients',
        sql: "SELECT dob FROM patients WHERE name = 'Jane'",
      }),
    ).rejects.toThrow(ScopeViolationError);
  });

  it('rejects encrypted columns out of scope in projection mode', async () => {
    const human = generateDidKey();
    const agentA = generateDidKey();
    const server = generateDidKey();

    const verifier = new VcVerifier({
      clockSkew: '30s',
      revocationStore: new InMemoryRevocationStore(),
    });
    verifier.registerKey(human.did, human.publicKey);
    verifier.registerKey(agentA.did, agentA.publicKey);
    verifier.registerKey(server.did, server.publicKey);

    const dobKey = generateColumnKey();
    const diagKey = generateColumnKey();
    const columnKeys = new Map<string, Buffer>([
      ['patients.dob', dobKey],
      ['patients.diagnosis', diagKey],
    ]);
    const encryptedColumns = new Set(['patients.dob', 'patients.diagnosis']);
    const sampleRows = [{ id: 1, dob: encrypt('1990-03-15', dobKey) }];
    const pool = {
      query: vi.fn().mockImplementation(async () => ({ rows: sampleRows, rowCount: 1 })),
    } as unknown as Pool;
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
    ]);
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
      scopeMode: 'projection',
      agentStore: { findByDid: vi.fn().mockResolvedValue(null) } as unknown as AgentStore,
    });

    const credential = await issueCredential(human.did, human.privateKey, {
      agent: agentA.did,
      columns: ['patients.dob', 'patients.id'],
      actions: ['read'],
      expiresIn: '4h',
    });

    // 'diagnosis' is encrypted AND not in scope — must be rejected in projection mode
    await expect(
      engine.query({
        agent: agentA.did,
        credential,
        table: 'patients',
        sql: 'SELECT dob, diagnosis FROM patients',
      }),
    ).rejects.toThrow(ScopeViolationError);
  });

  it('rejects out-of-scope column in HAVING clause', async () => {
    const human = generateDidKey();
    const agentA = generateDidKey();
    const server = generateDidKey();

    const verifier = new VcVerifier({
      clockSkew: '30s',
      revocationStore: new InMemoryRevocationStore(),
    });
    verifier.registerKey(human.did, human.publicKey);
    verifier.registerKey(agentA.did, agentA.publicKey);
    verifier.registerKey(server.did, server.publicKey);

    const dobKey = generateColumnKey();
    const columnKeys = new Map<string, Buffer>([['patients.dob', dobKey]]);
    const encryptedColumns = new Set(['patients.dob']);
    const pool = {
      query: vi.fn().mockImplementation(async () => ({ rows: [], rowCount: 0 })),
    } as unknown as Pool;
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
    ]);
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
      scopeMode: 'projection',
      agentStore: { findByDid: vi.fn().mockResolvedValue(null) } as unknown as AgentStore,
    });

    const credential = await issueCredential(human.did, human.privateKey, {
      agent: agentA.did,
      columns: ['patients.dob'],
      actions: ['read'],
      expiresIn: '4h',
    });

    // 'name' in HAVING clause is not in scope — extractAllReferencedColumns should catch it
    await expect(
      engine.query({
        agent: agentA.did,
        credential,
        table: 'patients',
        sql: 'SELECT dob FROM patients GROUP BY dob HAVING COUNT(name) > 1',
      }),
    ).rejects.toThrow(ScopeViolationError);
  });
});
