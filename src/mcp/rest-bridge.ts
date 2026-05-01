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

/**
 * MCP-over-REST Bridge — reference adapter.
 *
 * The current architecture direction is NOT to wire this bridge as the default
 * MCP implementation before publish. REST routes and MCP tools should instead
 * share transport-neutral application services. MCP must remain usable without
 * a REST server, and REST URLs/status codes should not become part of the MCP
 * public contract.
 *
 * This is source-only reference material. It is intentionally excluded from
 * ESM/CJS package builds and has no package.json export path. Do not import it
 * from consumer code or treat it as a supported adapter.
 */

import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { parseDuration } from '../config.js';

const expiresInDurationString = z
  .string()
  .min(1)
  .max(32)
  .superRefine((val, ctx) => {
    try {
      const ms = parseDuration(val);
      if (ms <= 0) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'Duration must be positive' });
      }
    } catch {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'Invalid duration format. Expected: "4h", "1d", "30m", etc.',
      });
    }
  });

const expiresInField = z.union([
  expiresInDurationString,
  z.number().int().positive().max(31_536_000),
]);

export interface RestBridgeConfig {
  /** Base URL of the REST API (e.g., "http://localhost:3100"). */
  baseUrl: string;
  /** Session ID for authenticated requests. Obtained via POST /auth/session. */
  sessionId: string;
}

/**
 * POST helper — calls a REST endpoint and returns the parsed JSON response.
 * Maps HTTP error codes to MCP isError responses.
 */
async function restPost(
  config: RestBridgeConfig,
  path: string,
  body: Record<string, unknown>,
  options?: { authenticated?: boolean },
): Promise<{ data: unknown; status: number }> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (options?.authenticated !== false) {
    headers['x-session'] = config.sessionId;
  }
  const res = await fetch(`${config.baseUrl}${path}`, {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
  });
  const data = await res.json();
  return { data, status: res.status };
}

async function restGet(
  config: RestBridgeConfig,
  path: string,
  options?: { authenticated?: boolean },
): Promise<{ data: unknown; status: number }> {
  const headers: Record<string, string> = {};
  if (options?.authenticated !== false) {
    headers['x-session'] = config.sessionId;
  }
  const res = await fetch(`${config.baseUrl}${path}`, { headers });
  const data = await res.json();
  return { data, status: res.status };
}

async function restDelete(
  config: RestBridgeConfig,
  path: string,
): Promise<{ data: unknown; status: number }> {
  const res = await fetch(`${config.baseUrl}${path}`, {
    method: 'DELETE',
    headers: { 'x-session': config.sessionId },
  });
  const data = await res.json().catch(() => ({}));
  return { data, status: res.status };
}

function mcpResult(data: unknown) {
  return { content: [{ type: 'text' as const, text: JSON.stringify(data) }] };
}

function mcpError(data: unknown) {
  return {
    content: [{ type: 'text' as const, text: JSON.stringify(data) }],
    isError: true as const,
  };
}

/**
 * Register MCP tools backed by REST API calls instead of direct SDK access.
 *
 * Pattern: each tool validates input via Zod (same schemas), then delegates
 * to a REST endpoint. The REST server handles all business logic, ceiling
 * enforcement, and audit logging. The MCP layer is pure plumbing.
 */
export function registerRestBridgeTools(server: McpServer, config: RestBridgeConfig): void {
  // ─── create-agent ────────────────────────────────────────────────
  server.tool(
    'create-agent',
    'Create a new agent identity (DID + keypair). Returns DID and public key.',
    {
      name: z.string().describe('Agent name'),
    },
    async ({ name }) => {
      const { data, status } = await restPost(config, '/agents', { name });
      return status >= 200 && status < 300 ? mcpResult(data) : mcpError(data);
    },
  );

  // ─── list-agents ─────────────────────────────────────────────────
  server.tool('list-agents', 'List agents owned by the authenticated human.', {}, async () => {
    const { data, status } = await restGet(config, '/agents');
    return status === 200 ? mcpResult(data) : mcpError(data);
  });

  // ─── issue-credential ───────────────────────────────────────────
  server.tool(
    'issue-credential',
    'Issue a Verifiable Credential JWT scoping an agent to specific columns.',
    {
      agent: z.string().describe('Agent DID'),
      columns: z.array(z.string()).describe('Columns to authorize'),
      actions: z.array(z.string()).optional().describe('Actions (default: ["read"])'),
      expiresIn: expiresInField.optional().describe('Expiry ("4h", "1d", or seconds)'),
    },
    async ({ agent, columns, actions, expiresIn }) => {
      const { data, status } = await restPost(config, '/credentials', {
        agent,
        columns,
        actions: actions ?? ['read'],
        expiresIn,
      });
      return status === 200 ? mcpResult(data) : mcpError(data);
    },
  );

  // ─── revoke-credential ──────────────────────────────────────────
  server.tool(
    'revoke-credential',
    'Revoke a previously issued credential by JTI.',
    {
      credentialId: z.string().describe('Credential JTI to revoke'),
    },
    async ({ credentialId }) => {
      const { data, status } = await restDelete(
        config,
        `/credentials/${encodeURIComponent(credentialId)}`,
      );
      return status >= 200 && status < 300 ? mcpResult(data) : mcpError(data);
    },
  );

  // ─── delegate-credential ────────────────────────────────────────
  server.tool(
    'delegate-credential',
    'Delegate a subset of a credential to another agent.',
    {
      sourceAgent: z.string().describe('Source agent DID'),
      sourceCredential: z.string().describe('Source credential JWT'),
      targetAgent: z.string().describe('Target agent DID'),
      columns: z.array(z.string()).describe('Columns to delegate (must be subset of source)'),
      actions: z.array(z.string()).optional().describe('Actions to delegate'),
      expiresIn: expiresInField.optional().describe('Expiry'),
    },
    async ({ sourceAgent, sourceCredential, targetAgent, columns, actions, expiresIn }) => {
      const { data, status } = await restPost(
        config,
        `/agents/${encodeURIComponent(sourceAgent)}/delegate`,
        { sourceCredential, targetAgent, columns, actions: actions ?? ['read'], expiresIn },
      );
      return status >= 200 && status < 300 ? mcpResult(data) : mcpError(data);
    },
  );

  // ─── query ───────────────────────────────────────────────────────
  server.tool(
    'query',
    'Execute a scoped SQL query with verifiable credential authorization.',
    {
      agent: z.string().describe('Agent DID'),
      credential: z.string().describe('JWT credential'),
      sql: z.string().describe('SQL SELECT query'),
      table: z.string().describe('Target table name'),
    },
    async ({ agent, credential, sql, table }) => {
      const { data, status } = await restPost(
        config,
        '/query',
        { agent, credential, sql, table },
        { authenticated: false },
      );
      return status === 200 ? mcpResult(data) : mcpError(data);
    },
  );

  // ─── export-audit ────────────────────────────────────────────────
  server.tool(
    'export-audit',
    'Export audit trail records. Optionally filter by agent DID.',
    {
      agent: z.string().optional().describe('Filter by agent DID'),
      limit: z.number().optional().describe('Max records to return'),
    },
    async ({ agent, limit }) => {
      const params = new URLSearchParams();
      if (agent) params.set('agent', agent);
      if (limit) params.set('limit', String(limit));
      const qs = params.toString();
      const { data, status } = await restGet(config, `/audit${qs ? `?${qs}` : ''}`);
      return status === 200 ? mcpResult(data) : mcpError(data);
    },
  );

  // ─── verify-audit ────────────────────────────────────────────────
  server.tool(
    'verify-audit',
    'Verify the cryptographic signature on an audit record.',
    {
      auditId: z.string().describe('Audit record ID'),
    },
    async ({ auditId }) => {
      const { data, status } = await restPost(config, '/audit/verify', { auditId });
      return status === 200 ? mcpResult(data) : mcpError(data);
    },
  );

  // ─── verify-chain ────────────────────────────────────────────────
  server.tool(
    'verify-chain',
    'Verify the audit hash chain integrity from GENESIS.',
    {
      limit: z.number().optional().describe('Max records to check'),
    },
    async ({ limit }) => {
      const { data, status } = await restPost(config, '/audit/verify-chain', {
        limit: limit ?? 1000,
      });
      return status === 200 ? mcpResult(data) : mcpError(data);
    },
  );

  // ─── whoami ─────────────────────────────────────────────────────
  server.tool('whoami', "Return the server's DID and current DID method.", {}, async () => {
    const { data, status } = await restGet(config, '/whoami', { authenticated: false });
    return status === 200 ? mcpResult(data) : mcpError(data);
  });

  // ─── sign ───────────────────────────────────────────────────────
  server.tool(
    'sign',
    "Sign an arbitrary payload with the server's Ed25519 key. Domain-separated.",
    {
      payload: z.string().describe('Payload string to sign (max 64KB)'),
    },
    async ({ payload }) => {
      const { data, status } = await restPost(config, '/sign', { payload });
      return status === 200 ? mcpResult(data) : mcpError(data);
    },
  );

  // ─── discover ───────────────────────────────────────────────────
  server.tool(
    'discover',
    "Discover the server's trust topology: DID, method, and trusted anchors.",
    {},
    async () => {
      const { data, status } = await restGet(config, '/discover', { authenticated: false });
      return status === 200 ? mcpResult(data) : mcpError(data);
    },
  );

  // ─── challenge ──────────────────────────────────────────────────
  server.tool(
    'challenge',
    'Issue a time-bound challenge for Verifiable Presentation requests.',
    {
      requestorDid: z.string().optional().describe('DID of the requesting agent'),
      ttlSeconds: z.number().optional().describe('Challenge TTL in seconds (default: 60)'),
    },
    async ({ requestorDid, ttlSeconds }) => {
      const body: Record<string, unknown> = {};
      if (requestorDid) body.requestorDid = requestorDid;
      if (ttlSeconds) body.ttlSeconds = ttlSeconds;
      const { data, status } = await restPost(config, '/challenge', body);
      return status === 200 ? mcpResult(data) : mcpError(data);
    },
  );
}
