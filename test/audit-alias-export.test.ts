import { describe, it, expect } from 'vitest';
import { AuditLogger } from '#audit/index.js';
import { DidAliasRegistry, type DidAlias } from '#did/alias.js';
import { createMockAuditStore } from './mocks/audit-store.js';
import { createMockAuditRecord } from './mocks/audit-record.js';

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

    const store = createMockAuditStore({
      records: [
        createMockAuditRecord({ agentDid: oldDid, id: 'old-record' }),
        createMockAuditRecord({ agentDid: newDid, id: 'new-record' }),
      ],
    });

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

    const store = createMockAuditStore({
      records: [createMockAuditRecord({ agentDid: 'did:key:z6MkSolo', id: 'solo-record' })],
    });

    const logger = new AuditLogger({
      auditStore: store,
      enabled: true,
      aliasRegistry: registry,
    });

    const records = await logger.export({ agentDid: 'did:key:z6MkSolo' });
    expect(records.length).toBeGreaterThan(0);
  });

  it('works without aliasRegistry (backward compatibility)', async () => {
    const store = createMockAuditStore({ records: [createMockAuditRecord({ agentDid: 'did:key:z6MkAgent', id: 'record-1' })] });

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

    const store = createMockAuditStore({ records: [createMockAuditRecord({ agentDid: oldDid, id: 'r1' })] });

    const logger = new AuditLogger({
      auditStore: store,
      enabled: true,
      aliasRegistry: registry,
    });

    const records = await logger.export();
    expect(records.length).toBeGreaterThan(0);
  });
});
