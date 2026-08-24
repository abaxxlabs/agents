import { vi } from 'vitest';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { AgentToolServices } from '#services/index.js';
import type { AuthenticatedSession } from '#types/auth.js';

export interface RegisteredMcpTool {
  name: string;
  description: string;
  schema: Record<string, unknown>;
  handler: (args: Record<string, unknown>) => Promise<unknown>;
}

export function createMockMcpServer(): McpServer & { _tools: RegisteredMcpTool[] } {
  const tools: RegisteredMcpTool[] = [];
  return {
    registerTool(
      name: string,
      config: { description: string; inputSchema: Record<string, unknown> },
      handler: (args: Record<string, unknown>) => Promise<unknown>,
    ) {
      tools.push({ name, description: config.description, schema: config.inputSchema, handler });
    },
    _tools: tools,
  } as unknown as McpServer & { _tools: RegisteredMcpTool[] };
}

export function getRegisteredMcpTool(
  server: McpServer & { _tools: RegisteredMcpTool[] },
  name: string,
): RegisteredMcpTool {
  const tool = server._tools.find((candidate) => candidate.name === name);
  if (!tool) throw new Error(`MCP tool not registered: ${name}`);
  return tool;
}

export function createMcpSession(): AuthenticatedSession {
  return {
    humanDid: 'did:key:human',
    parentIssuerDid: 'did:key:org',
    scopeCeiling: {
      columns: ['*'],
      actions: ['*'],
      source: 'mock-unrestricted',
      resolvedFrom: [],
    },
    issueCredential: vi.fn(async () => 'credential'),
    revokeCredential: vi.fn(async () => ({})),
  };
}

export function createAgentToolServiceFakes(): AgentToolServices {
  return {
    query: {
      execute: vi.fn(async () => ({
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
      })),
    },
    agents: {
      createAgent: vi.fn(async ({ name, ownerDid }) => ({
        did: 'did:key:agent',
        name,
        ownerDid: ownerDid ?? 'did:key:human',
        publicKey: new Uint8Array([1, 2, 3]),
      })),
      listAgents: vi.fn(async () => []),
    },
    credentials: {
      issueCredential: vi.fn(async () => ({ credential: 'issued-credential' })),
      delegateCredential: vi.fn(async () => ({ credential: 'delegated-credential' })),
      listCredentials: vi.fn(async () => ({ credentials: [], count: 0 })),
      revokeCredential: vi.fn(async ({ credentialId }) => ({ revoked: true, credentialId })),
    },
    audit: {
      exportAudit: vi.fn(async () => ({ records: [], count: 0 })),
      verifyAudit: vi.fn(async () => ({
        verified: true,
        status: 'VALID',
        record: { id: 'audit-1', agentDid: 'did:key:agent' },
        agentDid: 'did:key:agent',
      })),
      verifyChain: vi.fn(async () => ({ verified: true, recordsChecked: 0, brokenLinks: [] })),
    },
  } as unknown as AgentToolServices;
}

export function parseMcpToolPayload(result: unknown): Record<string, unknown> {
  const response = result as { content: Array<{ text: string }> };
  return JSON.parse(response.content[0].text) as Record<string, unknown>;
}
