import type { AuditRecord } from '#types/index.js';

export function createMockAuditRecord(overrides: Partial<AuditRecord> = {}): AuditRecord {
  return {
    id: 'test-uuid-1',
    timestamp: new Date().toISOString(),
    agentDid: 'did:key:zAgent1',
    ownerDid: 'did:key:zHuman1',
    credentialId: 'cred-hash-123',
    queryHash: 'query-hash-abc',
    columnsAccessed: ['col1'],
    rowCount: 1,
    durationMs: 10,
    previousHash: 'GENESIS',
    signature: 'jws-sig-xyz',
    version: 2,
    status: 'success',
    ...overrides,
  };
}
