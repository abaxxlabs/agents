import { describe, it, expect, vi } from 'vitest';
import { ScopeEngine } from '#sql/scope-engine.js';
import { VcVerifier } from '#identity/index.js';
import { decodeJwt } from '#crypto/jwt.js';
import { InMemoryRevocationStore } from '#storage/memory/revocation-store.js';
import { AuditLogger } from '#audit/index.js';
import type { AgentStore, AuditStore } from '#storage/types.js';
import type { Pool } from 'pg';
import {
  generateDidKey,
  issueCredential,
  issueDelegatedCredential,
  createSigner,
} from '#auth/index.js';
import type { AuditRecord, RegisteredAgent } from '#types/index.js';

function createFixture() {
  const human = generateDidKey();
  const supervisor = generateDidKey();
  const worker = generateDidKey();
  const server = generateDidKey();

  const verifier = new VcVerifier({
    clockSkew: '30s',
    revocationStore: new InMemoryRevocationStore(),
  });
  for (const k of [human, supervisor, worker, server]) {
    verifier.registerKey(k.did, k.publicKey);
  }

  const sampleRows = [{ id: 1, name: 'Jane Doe', dob: '1990-03-15' }];
  const pool = {
    query: vi.fn().mockImplementation(async (sql: string) => {
      if (sql.includes('INSERT INTO agent_audit')) return { rows: [], rowCount: 1 };
      if (sql.includes('SELECT') && sql.includes('patients')) {
        return { rows: sampleRows, rowCount: sampleRows.length };
      }
      return { rows: [], rowCount: 0 };
    }),
  } as unknown as Pool;

  const agent = (k: typeof human, name: string): RegisteredAgent => ({
    did: k.did,
    name,
    ownerDid: human.did,
    signer: createSigner(k.privateKey),
    publicKey: k.publicKey,
  });
  const agents = new Map<string, RegisteredAgent>([
    [supervisor.did, agent(supervisor, 'Supervisor')],
    [worker.did, agent(worker, 'Worker')],
  ]);

  const appended: AuditRecord[] = [];
  const auditStore: AuditStore = {
    append: vi.fn().mockImplementation(async (r: AuditRecord) => {
      appended.push(r);
    }),
    loadLastRecord: vi.fn().mockResolvedValue(null),
    loadLastRecordLocked: vi.fn().mockResolvedValue(null),
    query: vi.fn().mockResolvedValue([]),
    count: vi.fn().mockResolvedValue(0),
  };
  const auditLogger = new AuditLogger({ auditStore, enabled: true });

  const engine = new ScopeEngine({
    pool,
    verifier,
    auditLogger,
    columnKeys: new Map(),
    encryptedColumns: new Set(),
    agents,
    verifierDid: server.did,
    agentStore: { findByDid: vi.fn().mockResolvedValue(null) } as unknown as AgentStore,
  });

  return { human, supervisor, worker, verifier, auditLogger, engine, appended };
}

async function issueAndDelegate(f: ReturnType<typeof createFixture>) {
  const supervisorCred = await issueCredential(f.human.did, f.human.privateKey, {
    agent: f.supervisor.did,
    columns: ['patients.name', 'patients.dob'],
    actions: ['read'],
    expiresIn: '4h',
  });
  const sourceDecoded = decodeJwt(supervisorCred);
  const delegatedCred = await issueDelegatedCredential(
    f.supervisor.did,
    createSigner(f.supervisor.privateKey),
    supervisorCred,
    sourceDecoded.payload.jti ?? 'unknown',
    { columns: ['patients.name', 'patients.dob'], actions: ['read'] },
    {
      targetAgent: f.worker.did,
      columns: ['patients.name'],
      actions: ['read'],
      expiresIn: '1h',
      maxExpSeconds: sourceDecoded.payload.exp,
    },
  );
  return { supervisorCred, sourceJti: sourceDecoded.payload.jti, delegatedCred };
}

describe('delegated query audit provenance', () => {
  it('records the root human owner, the delegating agent, and the grant id', async () => {
    const f = createFixture();
    const { sourceJti, delegatedCred } = await issueAndDelegate(f);

    await f.engine.query({
      agent: f.worker.did,
      credential: delegatedCred,
      table: 'patients',
      sql: 'SELECT name FROM patients',
    });

    const record = f.appended.at(-1)!;
    expect(record.status).toBe('success');
    expect(record.ownerDid).toBe(f.human.did);
    expect(record.delegatorDid).toBe(f.supervisor.did);
    expect(record.delegatedGrantId).toBe(sourceJti);
    expect(record.version).toBe(4);
  });

  it('records delegation provenance on rejected delegated queries', async () => {
    const f = createFixture();
    const { sourceJti, delegatedCred } = await issueAndDelegate(f);

    await expect(
      f.engine.query({
        agent: f.worker.did,
        credential: delegatedCred,
        table: 'patients',
        sql: 'SELECT dob FROM patients',
      }),
    ).rejects.toThrow();

    const record = f.appended.at(-1)!;
    expect(record.status).toBe('rejected');
    expect(record.ownerDid).toBe(f.human.did);
    expect(record.delegatorDid).toBe(f.supervisor.did);
    expect(record.delegatedGrantId).toBe(sourceJti);
    expect(record.reasonCode).toBe('SCOPE_VIOLATION');
    expect(record.version).toBe(4);
  });
});
