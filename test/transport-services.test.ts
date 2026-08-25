import { describe, expect, it, vi } from 'vitest';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { registerResources, type ResourceServices } from '#mcp/resources.js';
import { registerTools } from '#mcp/tools.js';
import {
  createAgentDirectoryService,
  createAuditService,
  createCredentialService,
  createQueryService,
  createStatusService,
  type ServerStatus,
} from '#services/index.js';
import { FixedWindowRateLimiter } from '#transport/index.js';
import type { ServerIdentity } from '#identity/server-identity.js';
import type { AuditRecord } from '#types/index.js';
import { createAgentToolServiceFakes, createMcpSession, createMockMcpServer } from './mocks/mcp.js';
import { createMockAuditRecord } from './mocks/audit-record.js';

interface RegisteredResource {
  name: string;
  handler: (uri: URL, variables: Record<string, string | string[]>) => Promise<unknown>;
}

type MockResourceServer = ReturnType<typeof createMockMcpServer> & {
  _resources: RegisteredResource[];
};

function createMockResourceServer(): MockResourceServer {
  const server = createMockMcpServer();
  const resources: RegisteredResource[] = [];
  Object.assign(server, {
    registerResource(
      name: string,
      _uriOrTemplate: unknown,
      _config: unknown,
      handler: RegisteredResource['handler'],
    ) {
      resources.push({ name, handler });
    },
    _resources: resources,
  });
  return server as MockResourceServer;
}

function createResourceServiceFakes(): ResourceServices {
  const services = createAgentToolServiceFakes();
  return {
    ...services,
    agents: {
      ...services.agents,
      getAgent: vi.fn(),
    },
    audit: {
      ...services.audit,
      getRecentAudit: vi.fn(),
    },
    status: {
      getStatus: vi.fn(),
    },
  };
}

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
      agents: { createAgent: vi.fn(), getAgent, listAgents },
    });

    await expect(service.getAgent({ did: agent.did })).resolves.toEqual(agent);
    expect(getAgent).toHaveBeenCalledWith(agent.did);
    expect(listAgents).not.toHaveBeenCalled();

    const fallback = createAgentDirectoryService({
      agents: { createAgent: vi.fn(), listAgents },
    });
    expect(fallback.getAgent).toBeUndefined();
  });

  it('audit service returns the newest records without changing their order', async () => {
    const records = Array.from({ length: 55 }, (_, index) =>
      createMockAuditRecord({ id: `audit-${index}` }),
    );
    const auditReader = { export: vi.fn().mockResolvedValue(records) };
    const service = createAuditService({
      auditReader,
      verifier: { verify: vi.fn() },
    });

    const result = await service.getRecentAudit();

    expect(auditReader.export).toHaveBeenCalledWith();
    expect(result.records.map((record) => record.id)).toEqual(
      Array.from({ length: 50 }, (_, index) => `audit-${index + 5}`),
    );
    expect(result.count).toBe(50);
  });

  it('status service delegates status retrieval', async () => {
    const status = {
      agentCount: 2,
      auditRecordCount: 3,
      encryptedColumns: ['patients.dob'],
      inMemoryAgents: 2,
      scopeMode: 'projection' as const,
    };
    const getServerStatus = vi.fn().mockResolvedValue(status);
    const service = createStatusService({ statusReader: { getServerStatus } });

    await expect(service.getStatus()).resolves.toEqual(status);
    expect(getServerStatus).toHaveBeenCalledOnce();
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

  it('credential service keeps audit-derived credential listing transport neutral', async () => {
    const records = [
      {
        id: 'audit-1',
        timestamp: '2026-04-29T00:00:00.000Z',
        agentDid: 'did:key:agent',
        ownerDid: 'did:key:human',
        credentialId: 'cred-1',
      },
      {
        id: 'audit-2',
        timestamp: '2026-04-29T00:01:00.000Z',
        agentDid: 'did:key:other',
        ownerDid: 'did:key:other-human',
        credentialId: 'cred-2',
      },
    ] as AuditRecord[];

    const auditExport = vi.fn().mockResolvedValue(records);
    const service = createCredentialService({
      issuer: { issueCredential: vi.fn() },
      revoker: { revokeCredential: vi.fn() },
      delegator: { delegateCredential: vi.fn() },
      auditReader: { export: auditExport },
    });

    const result = await service.listCredentials({}, { ownerDid: 'did:key:human' });

    expect(auditExport).toHaveBeenCalledWith({
      ownerDid: 'did:key:human',
      limit: 500,
    });
    expect(result.credentials).toEqual([
      {
        credentialId: 'cred-1',
        agentDid: 'did:key:agent',
        ownerDid: 'did:key:human',
        issuedAt: '2026-04-29T00:00:00.000Z',
      },
    ]);
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

  it('verify-audit tool calls the shared audit service with session ownership', async () => {
    const services = createAgentToolServiceFakes();
    const server = createMockMcpServer();

    registerTools(server, { services, session: createMcpSession() });

    const tool = server._tools.find((candidate) => candidate.name === 'verify-audit')!;
    const result = await tool.handler({ auditId: 'audit-1' });

    expect(services.audit.verifyAudit).toHaveBeenCalledWith(
      { auditId: 'audit-1' },
      { ownerDid: 'did:key:human' },
    );
    const payload = result as { content: Array<{ text: string }> };
    expect(JSON.parse(payload.content[0].text)).toMatchObject({ verified: true });
  });

  it('sign tool uses shared limiter state across handler reconstruction', async () => {
    const limiter = new FixedWindowRateLimiter();
    const session = createMcpSession();
    const serverIdentity = {
      did: 'did:key:server',
      signer: { signJwt: vi.fn(() => 'signed-jwt') },
    };

    const serverA = createMockMcpServer();
    registerTools(serverA, {
      services: createAgentToolServiceFakes(),
      session,
      serverIdentity: serverIdentity as unknown as ServerIdentity,
      rateLimiter: limiter,
    });
    const signA = serverA._tools.find((candidate) => candidate.name === 'sign')!;
    for (let i = 0; i < 100; i++) {
      const result = await signA.handler({ payload: `payload-${i}` });
      expect(result).not.toMatchObject({ isError: true });
    }

    const serverB = createMockMcpServer();
    registerTools(serverB, {
      services: createAgentToolServiceFakes(),
      session,
      serverIdentity: serverIdentity as unknown as ServerIdentity,
      rateLimiter: limiter,
    });
    const signB = serverB._tools.find((candidate) => candidate.name === 'sign')!;
    const blocked = (await signB.handler({ payload: 'payload-101' })) as {
      content: Array<{ text: string }>;
      isError?: boolean;
    };

    expect(blocked.isError).toBe(true);
    expect(JSON.parse(blocked.content[0].text)).toMatchObject({
      error: 'RATE_LIMITED',
    });
  });
});

describe('MCP resources use shared services', () => {
  it('delegates all data retrieval and preserves resource payloads', async () => {
    const services = createResourceServiceFakes();
    const server = createMockResourceServer();
    const agent = {
      did: 'did:key:agent',
      name: 'Agent',
      ownerDid: 'did:key:human',
      createdAt: '2026-04-29T00:00:00.000Z',
    };
    const record = createMockAuditRecord({ id: 'audit-1', agentDid: agent.did });
    const status: ServerStatus = {
      agentCount: 1,
      auditRecordCount: 1,
      encryptedColumns: [],
      inMemoryAgents: 1,
      scopeMode: 'projection',
    };
    vi.mocked(services.agents.getAgent).mockResolvedValue(agent);
    vi.mocked(services.audit.getRecentAudit).mockResolvedValue({
      records: [record],
      count: 1,
    });
    vi.mocked(services.audit.verifyAudit).mockResolvedValue({
      verified: true,
      status: 'VALID',
      record,
      agentDid: agent.did,
    });
    vi.mocked(services.status.getStatus).mockResolvedValue(status);

    registerResources(server as unknown as McpServer, { services });

    const agentResult = await resourcePayload(server, 'agent-info', 'agent://resource', {
      did: agent.did,
    });
    const recentResult = await resourcePayload(server, 'audit-recent', 'audit://recent');
    const auditResult = await resourcePayload(server, 'audit-record', 'audit://audit-1', {
      id: 'audit-1',
    });
    const statusResult = await resourcePayload(server, 'config-status', 'config://status');

    expect(services.agents.getAgent).toHaveBeenCalledWith({ did: agent.did });
    expect(services.audit.getRecentAudit).toHaveBeenCalledWith({ limit: 50 });
    expect(services.audit.verifyAudit).toHaveBeenCalledWith({ auditId: 'audit-1' });
    expect(services.status.getStatus).toHaveBeenCalledOnce();
    expect(agentResult).toEqual(agent);
    expect(recentResult).toEqual({ records: [record], count: 1 });
    expect(auditResult).toEqual({ record, verified: true });
    expect(statusResult).toEqual(status);
  });

  it('preserves not-found responses from services', async () => {
    const services = createResourceServiceFakes();
    const server = createMockResourceServer();
    vi.mocked(services.agents.getAgent).mockResolvedValue(null);
    vi.mocked(services.audit.verifyAudit).mockResolvedValue({
      error: 'NOT_FOUND',
      message: 'Audit record audit-missing not found',
    });

    registerResources(server as unknown as McpServer, { services });

    await expect(
      resourcePayload(server, 'agent-info', 'agent://resource', {
        did: 'did:key:missing',
      }),
    ).resolves.toEqual({ error: 'NOT_FOUND', message: 'Agent did:key:missing not found' });
    await expect(
      resourcePayload(server, 'audit-record', 'audit://audit-missing', {
        id: 'audit-missing',
      }),
    ).resolves.toEqual({
      error: 'NOT_FOUND',
      message: 'Audit record audit-missing not found',
    });
  });
});

async function resourcePayload(
  server: MockResourceServer,
  name: string,
  uri: string,
  variables: Record<string, string | string[]> = {},
): Promise<unknown> {
  const resource = server._resources.find((candidate) => candidate.name === name)!;
  const result = (await resource.handler(new URL(uri), variables)) as {
    contents: Array<{ text: string }>;
  };
  return JSON.parse(result.contents[0].text);
}
