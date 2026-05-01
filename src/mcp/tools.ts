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
 * MCP tool handlers — 13 tools wrapping the AgentScope public API.
 * Identity tools (whoami, sign, discover, challenge) are only registered when
 * ServerIdentity + TrustAnchorStore are provided.
 */

import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { AgentScope } from '../sql/index.js';
import type { AuthenticatedSession } from '../types.js';
import type { AuditLogger } from '../audit-logger.js';
import type { ServerIdentity } from '../identity/server-identity.js';
import type { TrustAnchorStore } from '../discovery/trust-anchor.js';
import { createAgentToolServices, type AgentToolServices } from '../services/index.js';
import type { Logger } from '../logger.js';
import { defaultLogger } from '../logger.js';
import { ChallengeStore } from './challenge-store.js';
import {
  CHALLENGE_RATE_LIMIT,
  CHALLENGE_RATE_WINDOW_MS,
  SIGN_PAYLOAD_MAX_BYTES,
  SIGN_RATE_LIMIT,
  SIGN_RATE_WINDOW_MS,
  assertExpiresInBound,
  assertUtf8MaxBytes,
  assertWithinRateLimit,
  defaultIdentityRateLimiter,
  mcpToolInputShapes,
  normalizeDomainError,
  toMcpErrorBody,
  type RateLimiter,
} from '../transport/index.js';

// ─── Shared Error Mapper ─────────────────────────────────────────

function mapAgentScopeError(err: unknown, logger: Logger = defaultLogger): {
  content: Array<{ type: 'text'; text: string }>;
  isError: true;
} {
  const normalized = normalizeDomainError(err);
  // Never forward raw internal errors across the trust boundary.
  if (normalized.code === 'INTERNAL_ERROR' && err instanceof Error) {
    logger.error('[agents] Internal error in MCP tool handler: ' + err.message, {
      handler: 'tool', error: err.message,
    });
  }
  return {
    content: [{ type: 'text', text: JSON.stringify(toMcpErrorBody(normalized)) }],
    isError: true,
  };
}

// ─── Tool Registration ───────────────────────────────────────────

export interface ToolDependencies {
  session: AuthenticatedSession;
  services?: AgentToolServices;
  /** Optional diagnostic logger. */
  logger?: Logger;

  /**
   * Identity primitives. Optional — core tools work without them.
   * When provided, the 4 identity tools (whoami, sign, discover, challenge) are
   * registered. When absent, those tools are not available.
   */
  serverIdentity?: ServerIdentity;
  trustAnchorStore?: TrustAnchorStore;
  /**
   * ChallengeStore for the `challenge` tool. If not provided but serverIdentity is,
   * a default ChallengeStore is created with a random per-process HMAC secret.
   */
  challengeStore?: ChallengeStore;
  /**
   * Shared limiter for sign/challenge. REST-hosted MCP passes the same limiter
   * and principal key that REST uses so counters survive handler rebuilds and
   * callers cannot reset quotas by switching transports.
   */
  rateLimiter?: RateLimiter;
  /** Stable rate-limit key. Prefer the REST x-session token when available. */
  rateLimitPrincipal?: string;
  /** Current binding VC JWT (for whoami). */
  bindingVcJwt?: string;
  /** Binding VC expiry as Unix timestamp seconds (for whoami). */
  bindingExpiry?: number;
  /** Org domain from OrgBoundary extraction (for whoami). null = consumer account. */
  orgDomain?: string | null;
  /** Parsed credential.maxTtl in milliseconds (for expiresIn bound checks). */
  credentialMaxTtlMs?: number;
}

type ToolServiceFallbackDependencies = {
  scope?: AgentScope;
  auditLogger?: AuditLogger;
};

function resolveServices(
  deps: ToolDependencies & ToolServiceFallbackDependencies,
): AgentToolServices {
  if (deps.services) return deps.services;
  if (!deps.scope || !deps.auditLogger) {
    throw new Error('registerTools requires either services or scope+auditLogger dependencies.');
  }
  return createAgentToolServices({
    queryExecutor: deps.scope,
    agentDirectory: deps.scope,
    credentialIssuer: deps.session,
    credentialRevoker: deps.session,
    credentialDelegator: deps.scope,
    auditReader: deps.auditLogger,
    auditVerifier: deps.scope,
  });
}

export function registerTools(
  server: McpServer,
  deps: ToolDependencies & ToolServiceFallbackDependencies,
): void {
  const { session, credentialMaxTtlMs } = deps;
  const services = resolveServices(deps);
  const log = deps.logger ?? defaultLogger;

  // 1. query — Execute a scoped SQL query
  server.tool(
    'query',
    'Execute a scoped SQL query with an agent-signed Verifiable Presentation. Returns decrypted rows for in-scope columns, ciphertext for out-of-scope.',
    mcpToolInputShapes.query,
    async ({ agent, credential, sql, table, params }) => {
      try {
        const result = await services.query.execute(
          {
            agent,
            credential,
            sql,
            table,
            params,
            requirePresentation: true,
          },
          { orgId: session.parentIssuerDid },
        );

        return {
          content: [{ type: 'text' as const, text: JSON.stringify(result) }],
        };
      } catch (err) {
        return mapAgentScopeError(err, log);
      }
    },
  );

  // 2. create-agent — Create an agent identity
  server.tool(
    'create-agent',
    'Create a new agent identity (DID + keypair). Returns DID and public key — private key stays server-side.',
    {
      name: z.string().describe('Agent name'),
      ownerDid: z.string().optional().describe('Owner DID (defaults to session human)'),
    },
    async ({ name, ownerDid }) => {
      try {
        const createdAgent = await services.agents.createAgent({
          name,
          ownerDid: ownerDid ?? session.humanDid,
        });
        return {
          content: [
            {
              type: 'text' as const,
              text: JSON.stringify({
                did: createdAgent.did,
                name: createdAgent.name,
                ownerDid: createdAgent.ownerDid,
                publicKey: Buffer.from(createdAgent.publicKey).toString('base64'),
              }),
            },
          ],
        };
      } catch (err) {
        // Handle duplicate agent name
        if (
          (err instanceof Error && err.message.includes('duplicate key')) ||
          (err instanceof Error && err.message.includes('already exists'))
        ) {
          return {
            content: [
              {
                type: 'text' as const,
                text: JSON.stringify({
                  error: 'DUPLICATE_AGENT',
                  message: `Agent name '${name}' already exists`,
                }),
              },
            ],
            isError: true,
          };
        }
        return mapAgentScopeError(err, log);
      }
    },
  );

  // 3. issue-credential — Issue a scoped credential
  server.tool(
    'issue-credential',
    'Issue a Verifiable Credential JWT scoping an agent to specific columns.',
    {
      agent: z.string().describe('Agent DID'),
      columns: z
        .array(z.string())
        .describe('Columns to authorize (e.g., ["patients.name", "patients.dob"])'),
      actions: z.array(z.string()).optional().describe('Actions to authorize (default: ["read"])'),
      expiresIn: z
        .union([z.string(), z.number()])
        .optional()
        .describe('Expiry duration — string ("4h", "1d") or integer seconds (3600)'),
    },
    async ({ agent, columns, actions, expiresIn }) => {
      try {
        const resolvedExpiresIn = expiresIn ?? '4h';
        if (credentialMaxTtlMs !== undefined) {
          assertExpiresInBound(resolvedExpiresIn, credentialMaxTtlMs);
        }
        const result = await services.credentials.issueCredential({
          agent,
          columns,
          actions: (actions ?? ['read']) as 'read'[],
          expiresIn: resolvedExpiresIn,
        });
        return {
          content: [
            { type: 'text' as const, text: JSON.stringify({ credential: result.credential }) },
          ],
        };
      } catch (err) {
        return mapAgentScopeError(err, log);
      }
    },
  );

  // 4. revoke-credential — Revoke a credential
  server.tool(
    'revoke-credential',
    'Revoke a previously issued credential.',
    {
      credentialId: z.string().describe('Credential ID to revoke'),
    },
    async ({ credentialId }) => {
      try {
        await services.credentials.revokeCredential(
          { credentialId },
          { ownerDid: session.humanDid },
        );
        return {
          content: [
            { type: 'text' as const, text: JSON.stringify({ revoked: true, credentialId }) },
          ],
        };
      } catch (err) {
        return mapAgentScopeError(err, log);
      }
    },
  );

  // 5. delegate-credential — Delegate a credential to another agent
  server.tool(
    'delegate-credential',
    'Delegate a credential to another agent with a narrower scope. The delegated scope must be a subset of the source credential.',
    {
      sourceAgentDid: z.string().describe('DID of the agent that holds the source credential'),
      sourceCredential: z.string().describe('JWT of the source credential to delegate from'),
      targetAgent: z.string().describe('DID of the agent receiving the delegated credential'),
      columns: z.array(z.string()).describe('Columns to grant (must be subset of source)'),
      actions: z.array(z.string()).describe('Actions to grant (must be subset of source)'),
      expiresIn: z
        .union([z.string(), z.number()])
        .describe('Duration string ("1h", "30m") or seconds'),
    },
    async ({ sourceAgentDid, sourceCredential, targetAgent, columns, actions, expiresIn }) => {
      try {
        if (credentialMaxTtlMs !== undefined) {
          assertExpiresInBound(expiresIn, credentialMaxTtlMs);
        }
        const { credential } = await services.credentials.delegateCredential(
          {
            sourceAgentDid,
            sourceCredential,
            targetAgent,
            columns,
            actions,
            expiresIn,
          },
          { scopeCeiling: session.scopeCeiling },
        );
        return {
          content: [{ type: 'text' as const, text: JSON.stringify({ credential }) }],
        };
      } catch (err) {
        return mapAgentScopeError(err, log);
      }
    },
  );

  // 6. verify-audit — Verify an audit record's signature
  server.tool(
    'verify-audit',
    "Verify an audit record's Ed25519 signature against the agent's public key.",
    {
      auditId: z.string().describe('Audit record ID'),
    },
    async ({ auditId }) => {
      try {
        const result = await services.audit.verifyAudit(
          { auditId },
          { ownerDid: session.humanDid },
        );
        if ('error' in result) {
          return {
            content: [{ type: 'text' as const, text: JSON.stringify(result) }],
            isError: true,
          };
        }
        return {
          content: [{ type: 'text' as const, text: JSON.stringify(result) }],
        };
      } catch (err) {
        return mapAgentScopeError(err, log);
      }
    },
  );

  // 6. export-audit — Export audit trail with limit
  server.tool(
    'export-audit',
    'Export filtered audit records for compliance and reporting.',
    {
      agentDid: z.string().optional().describe('Filter by agent DID'),
      since: z.string().optional().describe('Filter since ISO date'),
      limit: z.number().optional().describe('Max records to return (default 100)'),
    },
    async ({ agentDid, since, limit }) => {
      try {
        const maxRecords = Math.min(limit ?? 100, 1000);
        let sinceDate: Date | undefined;
        if (since) {
          sinceDate = new Date(since);
          if (isNaN(sinceDate.getTime())) {
            return {
              content: [
                {
                  type: 'text' as const,
                  text: JSON.stringify({
                    error: 'INVALID_DATE',
                    message: `Invalid date: ${since}`,
                  }),
                },
              ],
              isError: true,
            };
          }
        }
        const result = await services.audit.exportAudit(
          {
            agentDid,
            since: sinceDate,
            limit: maxRecords,
          },
          { ownerDid: session.humanDid },
        );
        return {
          content: [{ type: 'text' as const, text: JSON.stringify(result) }],
        };
      } catch (err) {
        return mapAgentScopeError(err, log);
      }
    },
  );

  // 7. list-agents — List registered agents
  server.tool(
    'list-agents',
    'List registered agents and their metadata.',
    {
      ownerDid: z.string().optional().describe('Filter by owner DID'),
      limit: z.number().optional().describe('Max agents to return (default 100)'),
    },
    async ({ ownerDid, limit }) => {
      try {
        const agents = await services.agents.listAgents({
          ownerDid,
          limit: Math.min(limit ?? 100, 100),
        });
        return {
          content: [
            { type: 'text' as const, text: JSON.stringify({ agents, count: agents.length }) },
          ],
        };
      } catch (err) {
        return mapAgentScopeError(err, log);
      }
    },
  );

  // 8. verify-chain — Verify hash chain integrity
  server.tool(
    'verify-chain',
    'Verify the integrity of the audit hash chain. Reports any broken links.',
    {
      limit: z.number().optional().describe('Max records to verify (default 1000)'),
    },
    async ({ limit }) => {
      try {
        const result = await services.audit.verifyChain({ limit }, { ownerDid: session.humanDid });
        return {
          content: [{ type: 'text' as const, text: JSON.stringify(result) }],
        };
      } catch (err) {
        return mapAgentScopeError(err, log);
      }
    },
  );

  // ─── Identity Tools ─────────────────────────────────────────────
  if (!deps.serverIdentity) return;

  const { serverIdentity, trustAnchorStore } = deps;
  // Read bindingVcJwt/bindingExpiry/orgDomain from deps at call time, not here —
  // they are primitives that would snapshot stale values after binding refresh.
  const challengeStore = deps.challengeStore ?? new ChallengeStore();
  const rateLimiter = deps.rateLimiter ?? defaultIdentityRateLimiter;
  const rateLimitPrincipal = deps.rateLimitPrincipal ?? session.parentIssuerDid ?? session.humanDid;

  // 9. whoami — Return the current identity bundle
  server.tool(
    'whoami',
    'Return the current server identity bundle: server DID, human DID, org domain, binding credential, and DID method.',
    {},
    async () => {
      try {
        return {
          content: [
            {
              type: 'text' as const,
              text: JSON.stringify({
                serverDid: serverIdentity.did,
                humanDid: session.humanDid,
                orgDomain: deps.orgDomain ?? null,
                bindingVcJwt: deps.bindingVcJwt ?? null,
                bindingExpiry: deps.bindingExpiry ?? null,
                currentDidMethod: 'did:key' as const,
              }),
            },
          ],
        };
      } catch (err) {
        return mapAgentScopeError(err, log);
      }
    },
  );

  // 10. sign — returns a JWT (not raw bytes) because the key is an opaque closure.
  // Domain-separated prefix 'agents-sign-v1:' prevents cross-context reuse.
  server.tool(
    'sign',
    "Sign an arbitrary payload with the server's Ed25519 key. Returns a JWT containing the domain-separated payload. Max 64KB payload.",
    mcpToolInputShapes.sign,
    async ({ payload }) => {
      try {
        assertUtf8MaxBytes('payload', payload, SIGN_PAYLOAD_MAX_BYTES);
        assertWithinRateLimit(rateLimiter, {
          principal: rateLimitPrincipal,
          operation: 'sign',
          limit: SIGN_RATE_LIMIT,
          windowMs: SIGN_RATE_WINDOW_MS,
        });

        const prefixedPayload = `agents-sign-v1:${payload}`;

        const jwt = serverIdentity.signer.signJwt({
          iss: serverIdentity.did,
          iat: Math.floor(Date.now() / 1000),
          payload: prefixedPayload,
        });

        return {
          content: [
            {
              type: 'text' as const,
              text: JSON.stringify({
                signature: jwt,
                signerDid: serverIdentity.did,
                algorithm: 'Ed25519',
              }),
            },
          ],
        };
      } catch (err) {
        return mapAgentScopeError(err, log);
      }
    },
  );

  // 11. discover — List trusted anchors and identity topology
  server.tool(
    'discover',
    'List trusted server DIDs and the current identity topology. Shows the trust boundary this server recognizes.',
    {},
    async () => {
      try {
        return {
          content: [
            {
              type: 'text' as const,
              text: JSON.stringify({
                serverDid: serverIdentity.did,
                trustedAnchors: trustAnchorStore?.list() ?? [],
                didMethod: 'did:key' as const,
              }),
            },
          ],
        };
      } catch (err) {
        return mapAgentScopeError(err, log);
      }
    },
  );

  // 12. challenge — only issue() is exposed. consume() is server-side only;
  // exposing it would let an agent verify its own challenges (confused-deputy).
  server.tool(
    'challenge',
    'Issue a time-bound challenge for VP (Verifiable Presentation) requests. The challenge must be included in the VP to prove freshness.',
    mcpToolInputShapes.challenge,
    async ({ requestorDid, ttlSeconds }) => {
      try {
        assertWithinRateLimit(rateLimiter, {
          principal: rateLimitPrincipal,
          operation: 'challenge',
          limit: CHALLENGE_RATE_LIMIT,
          windowMs: CHALLENGE_RATE_WINDOW_MS,
        });
        const result = challengeStore.issue({ requestorDid, ttlSeconds });
        return {
          content: [
            {
              type: 'text' as const,
              text: JSON.stringify(result),
            },
          ],
        };
      } catch (err) {
        return mapAgentScopeError(err, log);
      }
    },
  );
}
