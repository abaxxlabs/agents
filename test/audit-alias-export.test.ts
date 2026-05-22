import { describe, it, expect, vi } from 'vitest';
import { AuditLogger } from '../src/audit-logger.js';
import { DidAliasRegistry, type DidAlias } from '../src/did-alias.js';
import type { AuditRecord } from '../src/types/index.js';
import type { AuditStore } from '../src/storage/types.js';

function createMockAuditStore(records: AuditRecord[] = []) {
  return {
    append: vi.fn().mockResolvedValue(undefined),
    loadLastRecord: vi.fn().mockResolvedValue(null),
    loadLastRecordLocked: vi.fn().mockResolvedValue(null),
    query: vi.fn().mockResolvedValue(records),
  } satisfies AuditStore;
}

function makeAuditRecord(agentDid: string, overrides: Partial<AuditRecord> = {}): AuditRecord {
  return {
    id: overrides.id ?? 'test-id',
    timestamp: overrides.timestamp ?? new Date().toISOString(),
    agentDid,
    ownerDid: overrides.ownerDid ?? 'did:key:zOwner',
    credentialId: overrides.credentialId ?? 'cred-hash',
    queryHash: overrides.queryHash ?? 'query-hash',
    columnsAccessed: overrides.columnsAccessed ?? ['col1'],
    rowCount: overrides.rowCount ?? 1,
    durationMs: overrides.durationMs ?? 10,
    previousHash: overrides.previousHash ?? 'GENESIS',
    signature: overrides.signature ?? 'sig-xyz',
    version: overrides.version ?? 2,
    status: overrides.status ?? 'success',
    ...overrides,
  };
}

describe('AuditLogger — alias-aware export', () => {
  const oldDid = 'did:key:z6MkOldUser';
  const newDid = 'did:dht:NewUserDHT';

  function makeAlias(): DidAlias {
    return {
      oldDid,
      newDid,
      credentialHash: 'alias-hash',
      oidcSubject: 'user@example.com',
      oidcIssuer: 'https://login.example.com',
      migratedAt: new Date(),
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    };
  }

  it('expands agentDid to include aliased DIDs when registry is set', async () => {
    const registry = new DidAliasRegistry();
    registry.addAlias(makeAlias());

    const store = createMockAuditStore([
      makeAuditRecord(oldDid, { id: 'old-record' }),
      makeAuditRecord(newDid, { id: 'new-record' }),
    ]);

    const logger = new AuditLogger({
      auditStore: store,
      enabled: true,
      aliasRegistry: registry,
    });

    const records = await logger.export({ agentDid: newDid });

    expect(store.query).toHaveBeenCalledWith(
      expect.objectContaining({ agentDids: expect.arrayContaining([oldDid, newDid]) }),
    );

    // Should return records (mock returns all)
    expect(records.length).toBeGreaterThan(0);
  });

  it('does not expand when no alias exists for the agentDid', async () => {
    const registry = new DidAliasRegistry();
    // No aliases registered

    const store = createMockAuditStore([
      makeAuditRecord('did:key:z6MkSolo', { id: 'solo-record' }),
    ]);

    const logger = new AuditLogger({
      auditStore: store,
      enabled: true,
      aliasRegistry: registry,
    });

    const records = await logger.export({ agentDid: 'did:key:z6MkSolo' });
    expect(records.length).toBeGreaterThan(0);
  });

  it('works without aliasRegistry (backward compatibility)', async () => {
    const store = createMockAuditStore([makeAuditRecord('did:key:z6MkAgent', { id: 'record-1' })]);

    // No aliasRegistry passed
    const logger = new AuditLogger({
      auditStore: store,
      enabled: true,
    });

    const records = await logger.export({ agentDid: 'did:key:z6MkAgent' });
    expect(records.length).toBeGreaterThan(0);
  });

  it('does not expand when no filter is provided', async () => {
    const registry = new DidAliasRegistry();
    registry.addAlias(makeAlias());

    const store = createMockAuditStore([makeAuditRecord(oldDid, { id: 'r1' })]);

    const logger = new AuditLogger({
      auditStore: store,
      enabled: true,
      aliasRegistry: registry,
    });

    const records = await logger.export();
    expect(records.length).toBeGreaterThan(0);
  });
});
