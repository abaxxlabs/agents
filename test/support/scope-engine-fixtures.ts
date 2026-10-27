import { vi } from 'vitest';
import type { Pool } from 'pg';
import { ScopeEngine } from '#sql/scope-engine.js';
import { VcVerifier } from '#identity/index.js';
import { InMemoryRevocationStore } from '#storage/memory/revocation-store.js';
import { AuditLogger } from '#audit/index.js';
import { encrypt, generateColumnKey } from '#encryption/index.js';
import { generateDidKey, createSigner } from '#auth/index.js';
import type { RegisteredAgent } from '#types/index.js';
import type { AgentStore } from '#storage/types.js';
import { createMockAuditStore } from '../mocks/audit-store.js';

export function createTestFixtures(auditOptions: Parameters<typeof createMockAuditStore>[0] = {}) {
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
    {
      id: 2,
      name: 'John Smith',
      dob: encrypt('1985-07-22', dobKey),
      diagnosis: encrypt('Hypertension', diagKey),
      ssn: encrypt('987-65-4321', ssnKey),
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

  const auditStore = createMockAuditStore(auditOptions);
  const auditLogger = new AuditLogger({
    auditStore,
    enabled: true,
  });

  const server = generateDidKey();
  verifier.registerKey(server.did, server.publicKey);

  const engine = new ScopeEngine({
    pool,
    verifier,
    auditLogger,
    columnKeys,
    encryptedColumns,
    agents,
    verifierDid: server.did,
    agentStore: {
      findByDid: vi.fn().mockResolvedValue(null),
      create: vi.fn(),
      list: vi.fn(),
      listAll: vi.fn(),
      count: vi.fn(),
    } as unknown as AgentStore,
  });

  return {
    human,
    agentA,
    agentB,
    engine,
    verifier,
    pool,
    columnKeys,
    encryptedColumns,
    auditStore,
  };
}
