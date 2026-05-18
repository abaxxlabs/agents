// Copyright 2026 Abaxx Technologies
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import { describe, expect, it, vi } from 'vitest';
import { sendDomainError } from '../packages/server/src/errors.js';
import { createAuditService, createCredentialService } from '../src/services/index.js';
import { PostgresAuditStore } from '../src/storage/postgres/audit-store.js';
import { SqliteAuditStore } from '../src/storage/sqlite/audit-store.js';
import type { AuditQueryFilter } from '../src/storage/types.js';
import type { AuditRecord } from '../src/types.js';

function createResponse() {
  return {
    statusCode: 200,
    body: undefined as unknown,
    status(code: number) {
      this.statusCode = code;
      return this;
    },
    json(body: unknown) {
      this.body = body;
      return this;
    },
  };
}

function auditRecord(overrides: Partial<AuditRecord> = {}): AuditRecord {
  return {
    id: 'audit-1',
    timestamp: '2026-04-29T00:00:00.000Z',
    agentDid: 'did:key:agent',
    ownerDid: 'did:key:owner',
    credentialId: 'cred-1',
    queryHash: 'hash',
    columnsAccessed: ['patients.name'],
    rowCount: 1,
    durationMs: 1,
    previousHash: 'GENESIS',
    signature: 'sig',
    version: 1,
    status: 'success',
    ...overrides,
  };
}

describe('safe REST error rendering', () => {
  it('returns a safe DTO for representative internal storage failures', () => {
    const res = createResponse();
    const err = new Error(
      'select * from agent_audit failed: postgresql://user:secret@db.internal:5432/app at /srv/private/server.ts:12',
    );

    const consoleError = vi.spyOn(console, 'error').mockImplementation(() => {});
    try {
      sendDomainError(res as unknown as Parameters<typeof sendDomainError>[0], err);
    } finally {
      consoleError.mockRestore();
    }

    expect(res.statusCode).toBe(500);
    expect(res.body).toEqual({
      error: 'INTERNAL_ERROR',
      code: 'INTERNAL_ERROR',
      message: 'An internal error occurred.',
    });
    expect(JSON.stringify(res.body)).not.toContain('secret');
    expect(JSON.stringify(res.body)).not.toContain('/srv/private');
    expect(JSON.stringify(res.body)).not.toContain('agent_audit');
  });
});

describe('service-level audit bounds', () => {
  it('exports audit records with owner, org, since, agent, and capped limit in the storage query', async () => {
    const exportSpy = vi.fn().mockResolvedValue([auditRecord({ orgId: 'did:key:org' })]);
    const service = createAuditService({
      auditReader: { export: exportSpy },
      verifier: { verify: vi.fn() },
    });
    const since = new Date('2026-04-01T00:00:00.000Z');

    const result = await service.exportAudit(
      { agentDid: 'did:key:agent', orgId: 'did:key:org', since, limit: 5_000 },
      { ownerDid: 'did:key:owner' },
    );

    expect(result.count).toBe(1);
    expect(exportSpy).toHaveBeenCalledWith({
      agentDid: 'did:key:agent',
      since,
      ownerDid: 'did:key:owner',
      orgId: 'did:key:org',
      limit: 1000,
    });
  });

  it('rejects unbounded audit exports with a safe validation error', async () => {
    const service = createAuditService({
      auditReader: { export: vi.fn() },
      verifier: { verify: vi.fn() },
    });

    await expect(service.exportAudit({ limit: 50 }, {})).rejects.toMatchObject({
      code: 'VALIDATION_FAILED',
      issues: [{ path: 'audit', code: 'bounded_filter_required' }],
    });
  });

  it('verifies a single audit record by ID without exporting unrelated records', async () => {
    const record = auditRecord({ id: 'audit-target', orgId: 'did:key:org' });
    const exportSpy = vi.fn().mockResolvedValue([record]);
    const verifySpy = vi.fn().mockResolvedValue({ valid: true, status: 'VALID' });
    const service = createAuditService({
      auditReader: { export: exportSpy },
      verifier: { verify: verifySpy },
    });

    const result = await service.verifyAudit(
      { auditId: 'audit-target' },
      { ownerDid: 'did:key:owner', orgId: 'did:key:org' },
    );

    expect(exportSpy).toHaveBeenCalledWith({
      id: 'audit-target',
      ownerDid: 'did:key:owner',
      orgId: 'did:key:org',
      limit: 1,
    });
    expect(result).toMatchObject({ verified: true, agentDid: 'did:key:agent' });
  });

  it('lists and revokes credentials through bounded audit filters', async () => {
    const exportSpy = vi.fn(async (filter?: AuditQueryFilter) => {
      if (filter?.credentialId) return [auditRecord({ credentialId: filter.credentialId })];
      return [auditRecord({ credentialId: 'cred-1' })];
    });
    const revokeSpy = vi.fn().mockResolvedValue({});
    const service = createCredentialService({
      issuer: { issueCredential: vi.fn() },
      revoker: { revokeCredential: revokeSpy },
      delegator: { delegateCredential: vi.fn() },
      auditReader: { export: exportSpy },
    });
    const since = new Date('2026-04-01T00:00:00.000Z');

    await service.listCredentials(
      { agentDid: 'did:key:agent', issuedAfter: since, limit: 25 },
      { ownerDid: 'did:key:owner' },
    );
    await service.revokeCredential({ credentialId: 'cred-1' }, { ownerDid: 'did:key:owner' });

    expect(exportSpy).toHaveBeenNthCalledWith(1, {
      ownerDid: 'did:key:owner',
      agentDid: 'did:key:agent',
      since,
      limit: 25,
    });
    expect(exportSpy).toHaveBeenNthCalledWith(2, {
      credentialId: 'cred-1',
      ownerDid: 'did:key:owner',
      limit: 1,
    });
    expect(revokeSpy).toHaveBeenCalledWith('cred-1');
  });
});

describe('storage-level audit limits', () => {
  it('adds WHERE predicates and LIMIT to Postgres audit queries', async () => {
    const pool = {
      query: vi.fn().mockResolvedValue({ rows: [] }),
    };
    const store = new PostgresAuditStore(
      pool as unknown as ConstructorParameters<typeof PostgresAuditStore>[0],
    );
    const since = new Date('2026-04-01T00:00:00.000Z');

    await store.query({
      id: 'audit-1',
      agentDid: 'did:key:agent',
      since,
      ownerDid: 'did:key:owner',
      credentialId: 'cred-1',
      orgId: 'did:key:org',
      limit: 25,
    });

    const [sql, params] = pool.query.mock.calls[0];
    expect(sql).toContain('id = $1');
    expect(sql).toContain('agent_did = $2');
    expect(sql).toContain('timestamp >= $3');
    expect(sql).toContain('owner_did = $4');
    expect(sql).toContain('credential_id = $5');
    expect(sql).toContain('org_id = $6');
    expect(sql).toContain('LIMIT $7');
    expect(params).toEqual([
      'audit-1',
      'did:key:agent',
      since.toISOString(),
      'did:key:owner',
      'cred-1',
      'did:key:org',
      25,
    ]);
  });

  it('adds WHERE predicates and LIMIT to SQLite audit queries', async () => {
    const all = vi.fn().mockReturnValue([]);
    const prepare = vi.fn().mockReturnValue({ all });
    const store = new SqliteAuditStore({ prepare } as unknown as ConstructorParameters<
      typeof SqliteAuditStore
    >[0]);

    await store.query({
      ownerDid: 'did:key:owner',
      orgId: 'did:key:org',
      limit: 10,
    });

    const sql = prepare.mock.calls[0][0] as string;
    expect(sql).toContain('owner_did = ?');
    expect(sql).toContain('org_id = ?');
    expect(sql).toContain('LIMIT ?');
    expect(all).toHaveBeenCalledWith('did:key:owner', 'did:key:org', 10);
  });
});
