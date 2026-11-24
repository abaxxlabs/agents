import { describe, expect, it, vi } from 'vitest';
import { registerTools } from '#mcp/tools.js';
import {
  createAgentDirectoryService,
  createAuditService,
  createQueryService,
} from '#services/index.js';
import type { AuditRecord } from '#types/index.js';
import { createAgentToolServiceFakes, createMcpSession, createMockMcpServer } from './mocks/mcp.js';

describe('transport-neutral services', () => {
  it('agent directory service owns lookup by DID', async () => {
    const agent = {
      did: 'did:key:agent',
      name: 'Agent',
      ownerDid: 'did:key:human',
      createdAt: '2026-04-29T00:00:00.000Z',
    };
    const listAgents = vi.fn().mockResolvedValue([agent]);
    const getAgent = vi.fn().mockResolvedValue(agent);
    const service = createAgentDirectoryService({
      agents: { createAgentIdentity: vi.fn(), getAgent, listAgents },
    });

    await expect(service.getAgent?.({ did: agent.did })).resolves.toEqual(agent);
    expect(getAgent).toHaveBeenCalledWith(agent.did);
    expect(listAgents).not.toHaveBeenCalled();

    const fallback = createAgentDirectoryService({
      agents: { createAgentIdentity: vi.fn(), listAgents },
    });
    expect(fallback.getAgent).toBeUndefined();
  });
  it('query service delegates domain execution and owns the shared row cap', async () => {
    const executor = {
      query: vi.fn().mockResolvedValue({
        rows: Array.from({ length: 3 }, (_, id) => ({ id })),
        metadata: {
          agent: 'did:key:agent',
          owner: 'did:key:human',
          columnsDecrypted: [],
          columnsEncrypted: [],
          rowCount: 3,
          queryDurationMs: 1,
          auditId: 'audit-1',
        },
      }),
    };

    const service = createQueryService({ executor, maxRows: 2 });
    const result = await service.execute(
      {
        agent: 'did:key:agent',
        credential: 'jwt',
        sql: 'SELECT id FROM patients',
        table: 'patients',
        requirePresentation: true,
      },
      { orgId: 'did:key:org' },
    );

    expect(executor.query).toHaveBeenCalledWith(
      expect.objectContaining({
        agent: 'did:key:agent',
        orgId: 'did:key:org',
        requirePresentation: true,
      }),
    );
    expect(result.rows).toHaveLength(2);
    expect(result.metadata.rowCount).toBe(2);
  });

  it('audit service verifies records through the shared path', async () => {
    const record = {
      id: 'audit-1',
      timestamp: '2026-04-29T00:00:00.000Z',
      agentDid: 'did:key:agent',
      ownerDid: 'did:key:human',
      credentialId: 'cred-1',
      queryHash: 'hash',
      columnsAccessed: ['patients.id'],
      rowCount: 1,
      durationMs: 1,
      previousHash: 'GENESIS',
      signature: 'sig',
      version: 1,
    } as AuditRecord;

    const service = createAuditService({
      auditReader: { export: vi.fn().mockResolvedValue([record]) },
      verifier: { verify: vi.fn().mockResolvedValue({ valid: true, status: 'VALID' }) },
    });

    const result = await service.verifyAudit({ auditId: 'audit-1' }, { ownerDid: 'did:key:human' });

    expect(result).toMatchObject({ verified: true, status: 'VALID', agentDid: 'did:key:agent' });
  });
});

describe('MCP tools use shared services', () => {
  it('query tool calls the shared query service without parsing SQL locally', async () => {
    const services = createAgentToolServiceFakes();
    const server = createMockMcpServer();

    registerTools(server, { services, session: createMcpSession() });

    const tool = server._tools.find((candidate) => candidate.name === 'query')!;
    await tool.handler({
      agent: 'did:key:agent',
      credential: 'jwt',
      sql: 'SELECT id FROM patients',
      table: 'patients',
      params: [1],
    });

    expect(services.query.execute).toHaveBeenCalledWith(
      {
        agent: 'did:key:agent',
        credential: 'jwt',
        sql: 'SELECT id FROM patients',
        table: 'patients',
        params: [1],
        requirePresentation: true,
      },
      { orgId: 'did:key:org' },
    );
  });
});
