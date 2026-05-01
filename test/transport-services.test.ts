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
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { registerTools } from '../src/mcp/tools.js';
import {
  createAuditService,
  createCredentialService,
  createQueryService,
  type AgentToolServices,
} from '../src/services/index.js';
import { FixedWindowRateLimiter } from '../src/transport/index.js';
import type { ServerIdentity } from '../src/identity/server-identity.js';
import type { AuditRecord, AuthenticatedSession } from '../src/types.js';

interface RegisteredTool {
  name: string;
  description: string;
  schema: Record<string, unknown>;
  handler: (args: Record<string, unknown>) => Promise<unknown>;
}

function createMockMcpServer() {
  const tools: RegisteredTool[] = [];
  return {
    tool(
      name: string,
      description: string,
      schema: Record<string, unknown>,
      handler: (args: Record<string, unknown>) => Promise<unknown>,
    ) {
      tools.push({ name, description, schema, handler });
    },
    _tools: tools,
  };
}

function createSession(): AuthenticatedSession {
  return {
    humanDid: 'did:key:human',
    parentIssuerDid: 'did:key:org',
    scopeCeiling: {
      columns: ['*'],
      actions: ['*'],
      source: 'mock-unrestricted',
      resolvedFrom: [],
    },
    issueCredential: vi.fn(),
    revokeCredential: vi.fn(),
  };
}

function createServiceFakes(): AgentToolServices {
  return {
    query: {
      execute: vi.fn().mockResolvedValue({
        rows: [{ id: 1 }],
        metadata: {
          agent: 'did:key:agent',
          owner: 'did:key:human',
          columnsDecrypted: [],
          columnsEncrypted: [],
          rowCount: 1,
          queryDurationMs: 1,
          auditId: 'audit-1',
        },
      }),
    },
    agents: {
      createAgent: vi.fn(),
      listAgents: vi.fn(),
    },
    credentials: {
      issueCredential: vi.fn(),
      delegateCredential: vi.fn(),
      listCredentials: vi.fn(),
      revokeCredential: vi.fn(),
    },
    audit: {
      exportAudit: vi.fn(),
      verifyAudit: vi.fn().mockResolvedValue({
        verified: true,
        status: 'VALID',
        record: { id: 'audit-1', agentDid: 'did:key:agent' },
        agentDid: 'did:key:agent',
      }),
      verifyChain: vi.fn(),
    },
  } as unknown as AgentToolServices;
}

describe('transport-neutral services', () => {
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
    const services = createServiceFakes();
    const server = createMockMcpServer();

    registerTools(server as unknown as McpServer, { services, session: createSession() });

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
    const services = createServiceFakes();
    const server = createMockMcpServer();

    registerTools(server as unknown as McpServer, { services, session: createSession() });

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
    const session = createSession();
    const serverIdentity = {
      did: 'did:key:server',
      signer: { signJwt: vi.fn(() => 'signed-jwt') },
    };

    const serverA = createMockMcpServer();
    registerTools(serverA as unknown as McpServer, {
      services: createServiceFakes(),
      session,
      serverIdentity: serverIdentity as unknown as ServerIdentity,
      rateLimiter: limiter,
      rateLimitPrincipal: 'session-1',
    });
    const signA = serverA._tools.find((candidate) => candidate.name === 'sign')!;
    for (let i = 0; i < 100; i++) {
      const result = await signA.handler({ payload: `payload-${i}` });
      expect(result).not.toMatchObject({ isError: true });
    }

    const serverB = createMockMcpServer();
    registerTools(serverB as unknown as McpServer, {
      services: createServiceFakes(),
      session,
      serverIdentity: serverIdentity as unknown as ServerIdentity,
      rateLimiter: limiter,
      rateLimitPrincipal: 'session-1',
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
