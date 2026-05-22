import { describe, it, expect } from 'vitest';
import { createAgentToolServices } from '../src/services/index.js';
import type {
  QueryExecutor,
  AgentDirectory,
  CredentialIssuer,
  CredentialRevoker,
  CredentialDelegator,
  AuditVerifier,
} from '../src/services/index.js';
import type { AuditRecord } from '../src/types/index.js';
import type { AuditQueryFilter } from '../src/storage/types.js';
import type { AgentScope } from '../src/sql/index.js';
import type { Request, Response, NextFunction } from 'express';
import { loadServerConfig } from '../packages/server/src/config.js';
import { parseIssuedAfterQuery } from '../packages/server/src/routes.js';
import {
  createRequireSessionMiddleware,
  createSessionManager,
} from '../packages/server/src/session.js';

interface CredentialRecord {
  credentialId: string;
  agentDid: string;
  ownerDid: string;
  issuedAt: string;
}

const HUMAN_A = 'did:key:zHumanA';
const HUMAN_B = 'did:key:zHumanB';
const AGENT_1 = 'did:key:zAgent1';
const AGENT_2 = 'did:key:zAgent2';

function makeAuditRecord(
  overrides: Partial<AuditRecord> & {
    ownerDid: string;
    agentDid: string;
    credentialId: string;
    timestamp: string;
  },
): Pick<AuditRecord, 'credentialId' | 'agentDid' | 'ownerDid' | 'timestamp'> {
  return {
    credentialId: overrides.credentialId,
    agentDid: overrides.agentDid,
    ownerDid: overrides.ownerDid,
    timestamp: overrides.timestamp,
  };
}

async function listCredentials(
  records: Pick<AuditRecord, 'credentialId' | 'agentDid' | 'ownerDid' | 'timestamp'>[],
  humanDid: string,
  input: { agentDid?: string; issuedAfter?: Date } = {},
): Promise<CredentialRecord[]> {
  const services = createAgentToolServices({
    queryExecutor: {} as unknown as QueryExecutor,
    agentDirectory: {} as unknown as AgentDirectory,
    credentialIssuer: {} as unknown as CredentialIssuer,
    credentialRevoker: {} as unknown as CredentialRevoker,
    credentialDelegator: {} as unknown as CredentialDelegator,
    auditReader: {
      export: async (filter?: AuditQueryFilter) => {
        let filtered = records;
        if (filter?.agentDid) filtered = filtered.filter((r) => r.agentDid === filter.agentDid);
        if (filter?.ownerDid) filtered = filtered.filter((r) => r.ownerDid === filter.ownerDid);
        if (filter?.since)
          filtered = filtered.filter((r) => new Date(r.timestamp) >= filter.since!);
        if (filter?.limit) filtered = filtered.slice(0, filter.limit);
        return filtered as AuditRecord[];
      },
    },
    auditVerifier: {} as unknown as AuditVerifier,
  });

  const result = await services.credentials.listCredentials(input, { ownerDid: humanDid });
  return result.credentials;
}

describe('GET /credentials — auth gate', () => {
  it('returns 401 shape when session is missing', () => {
    const config = loadServerConfig({ NODE_ENV: 'test' });
    const sessionManager = createSessionManager({
      config,
      scopeProvider: () => ({}) as unknown as AgentScope,
    });
    const middleware = createRequireSessionMiddleware(sessionManager);
    const res = {
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

    middleware(
      { headers: {} } as unknown as Request,
      res as unknown as Response,
      (() => undefined) as NextFunction,
    );

    expect(res.statusCode).toBe(401);
    expect(res.body).toEqual({ error: 'Missing x-session header. Call POST /auth/session first.' });
  });
});

describe('GET /credentials — credential service listing', () => {
  const records = [
    makeAuditRecord({
      ownerDid: HUMAN_A,
      agentDid: AGENT_1,
      credentialId: 'cred-hash-1',
      timestamp: '2026-01-01T01:00:00Z',
    }),
    makeAuditRecord({
      ownerDid: HUMAN_A,
      agentDid: AGENT_1,
      credentialId: 'cred-hash-1',
      timestamp: '2026-01-01T02:00:00Z',
    }),
    makeAuditRecord({
      ownerDid: HUMAN_A,
      agentDid: AGENT_2,
      credentialId: 'cred-hash-2',
      timestamp: '2026-01-02T00:00:00Z',
    }),
    makeAuditRecord({
      ownerDid: HUMAN_B,
      agentDid: AGENT_1,
      credentialId: 'cred-hash-3',
      timestamp: '2026-01-03T00:00:00Z',
    }),
  ];

  it('returns credentials visible to the authenticated caller', async () => {
    const result = await listCredentials(records, HUMAN_A);
    expect(result).toHaveLength(2);
    const ids = result.map((r) => r.credentialId);
    expect(ids).toContain('cred-hash-1');
    expect(ids).toContain('cred-hash-2');
    expect(ids).not.toContain('cred-hash-3');
  });

  it('deduplicates same credentialId+agentDid with earliest timestamp', async () => {
    const result = await listCredentials(records, HUMAN_A);
    const cred1 = result.find((r) => r.credentialId === 'cred-hash-1');
    expect(cred1).toBeDefined();
    expect(cred1!.issuedAt).toBe('2026-01-01T01:00:00Z');
  });

  it('returns empty array when caller has no credentials', async () => {
    await expect(listCredentials(records, 'did:key:zUnknown')).resolves.toHaveLength(0);
  });

  it('returns empty array when audit records list is empty', async () => {
    const result = await listCredentials([], HUMAN_A);
    expect(result).toHaveLength(0);
    expect(Array.isArray(result)).toBe(true);
  });
});

describe('GET /credentials — filters', () => {
  const records = [
    makeAuditRecord({
      ownerDid: HUMAN_A,
      agentDid: AGENT_1,
      credentialId: 'cred-hash-old',
      timestamp: '2026-01-01T00:00:00Z',
    }),
    makeAuditRecord({
      ownerDid: HUMAN_A,
      agentDid: AGENT_2,
      credentialId: 'cred-hash-new',
      timestamp: '2026-03-01T00:00:00Z',
    }),
  ];

  it('agentDid filter returns credentials for the specified agent', async () => {
    const result = await listCredentials(records, HUMAN_A, { agentDid: AGENT_1 });
    expect(result).toHaveLength(1);
    expect(result[0].agentDid).toBe(AGENT_1);
    expect(result[0].credentialId).toBe('cred-hash-old');
  });

  it('agentDid filter with no matching records returns empty array', async () => {
    await expect(
      listCredentials(records, HUMAN_A, { agentDid: 'did:key:zNonexistent' }),
    ).resolves.toHaveLength(0);
  });

  it('issuedAfter filter returns credentials first seen after the timestamp', async () => {
    const result = await listCredentials(records, HUMAN_A, {
      issuedAfter: new Date('2026-02-01T00:00:00Z'),
    });
    expect(result).toHaveLength(1);
    expect(result[0].credentialId).toBe('cred-hash-new');
  });

  it('both agentDid and issuedAfter compose with AND semantics', async () => {
    const result = await listCredentials(records, HUMAN_A, {
      agentDid: AGENT_2,
      issuedAfter: new Date('2026-02-01T00:00:00Z'),
    });
    expect(result).toHaveLength(1);
    expect(result[0].credentialId).toBe('cred-hash-new');
    expect(result[0].agentDid).toBe(AGENT_2);
  });

  it('issuedAfter in the future returns empty array', async () => {
    await expect(
      listCredentials(records, HUMAN_A, { issuedAfter: new Date('2030-01-01T00:00:00Z') }),
    ).resolves.toHaveLength(0);
  });
});

describe('GET /credentials — issuedAfter validation', () => {
  it('undefined means no filter', () => {
    expect(parseIssuedAfterQuery(undefined)).toBeUndefined();
  });

  it('valid ISO-8601 returns a Date object', () => {
    const result = parseIssuedAfterQuery('2020-06-15T12:00:00Z');
    expect(result).toBeInstanceOf(Date);
    expect((result as Date).toISOString()).toBe('2020-06-15T12:00:00.000Z');
  });

  it('invalid string returns "invalid"', () => {
    expect(parseIssuedAfterQuery('not-a-date')).toBe('invalid');
  });

  it('empty string returns "invalid"', () => {
    expect(parseIssuedAfterQuery('')).toBe('invalid');
  });
});

describe('GET /credentials — response shape', () => {
  it('result object has credentialId, agentDid, ownerDid, issuedAt fields', async () => {
    const records = [
      makeAuditRecord({
        ownerDid: HUMAN_A,
        agentDid: AGENT_1,
        credentialId: 'cred-001',
        timestamp: '2026-01-01T00:00:00Z',
      }),
    ];
    const result = await listCredentials(records, HUMAN_A);
    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject({
      credentialId: 'cred-001',
      agentDid: AGENT_1,
      ownerDid: HUMAN_A,
      issuedAt: '2026-01-01T00:00:00Z',
    });
  });
});
