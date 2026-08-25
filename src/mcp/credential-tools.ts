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

import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { AgentToolServices } from '#services/index.js';
import type { AuthenticatedSession } from '#types/auth.js';
import type { Logger } from '#observability/logger.js';
import {
  CREDENTIAL_MINT_OPERATION,
  CREDENTIAL_MINT_RATE_LIMIT,
  CREDENTIAL_MINT_RATE_WINDOW_MS,
  assertExpiresInBound,
  assertWithinRateLimit,
  defaultIdentityRateLimiter,
  type RateLimiter,
} from '#transport/index.js';
import { mapAgentScopeError } from './tool-errors.js';

interface CredentialToolDependencies {
  services: Pick<AgentToolServices, 'credentials'>;
  session: AuthenticatedSession;
  credentialMaxTtlMs?: number;
  rateLimiter?: RateLimiter;
  logger?: Logger;
}

/** Issuance and delegation share one quota so neither can be used to bypass the other. */
function assertWithinMintQuota(deps: CredentialToolDependencies): void {
  assertWithinRateLimit(deps.rateLimiter ?? defaultIdentityRateLimiter, {
    principal: deps.session.humanDid,
    operation: CREDENTIAL_MINT_OPERATION,
    limit: CREDENTIAL_MINT_RATE_LIMIT,
    windowMs: CREDENTIAL_MINT_RATE_WINDOW_MS,
  });
}

export function registerIssueCredentialTool(
  server: McpServer,
  deps: CredentialToolDependencies,
): void {
  server.registerTool(
    'issue-credential',
    {
      description: 'Issue a Verifiable Credential JWT scoping an agent to specific columns.',
      inputSchema: {
        agent: z.string().describe('Agent DID'),
        columns: z
          .array(z.string())
          .describe('Columns to authorize (e.g., ["patients.name", "patients.dob"])'),
        actions: z
          .array(z.string())
          .optional()
          .describe('Actions to authorize (default: ["read"])'),
        expiresIn: z
          .union([z.string(), z.number()])
          .optional()
          .describe('Expiry duration — string ("4h", "1d") or integer seconds (3600)'),
        maxDepth: z
          .number()
          .int()
          .min(1)
          .max(10)
          .optional()
          .describe(
            'Maximum delegation chain depth embedded in the issued credential. Default: 2. Pass 1 to prevent any delegation.',
          ),
      },
    },
    async ({ agent, columns, actions, expiresIn, maxDepth }) => {
      try {
        const resolvedExpiresIn = expiresIn ?? '4h';
        if (deps.credentialMaxTtlMs !== undefined) {
          assertExpiresInBound(resolvedExpiresIn, deps.credentialMaxTtlMs);
        }
        assertWithinMintQuota(deps);
        const result = await deps.services.credentials.issueCredential({
          agent,
          columns,
          actions: (actions ?? ['read']) as 'read'[],
          expiresIn: resolvedExpiresIn,
          ...(maxDepth !== undefined ? { maxDepth } : {}),
        });
        return {
          content: [
            { type: 'text' as const, text: JSON.stringify({ credential: result.credential }) },
          ],
        };
      } catch (err) {
        return mapAgentScopeError(err, deps.logger);
      }
    },
  );
}

export function registerRevokeCredentialTool(
  server: McpServer,
  deps: CredentialToolDependencies,
): void {
  server.registerTool(
    'revoke-credential',
    {
      description: 'Revoke a previously issued credential.',
      inputSchema: {
        credentialId: z.string().describe('Credential ID to revoke'),
      },
    },
    async ({ credentialId }) => {
      try {
        await deps.services.credentials.revokeCredential(
          { credentialId },
          { ownerDid: deps.session.humanDid },
        );
        return {
          content: [
            { type: 'text' as const, text: JSON.stringify({ revoked: true, credentialId }) },
          ],
        };
      } catch (err) {
        return mapAgentScopeError(err, deps.logger);
      }
    },
  );
}

export function registerDelegateCredentialTool(
  server: McpServer,
  deps: CredentialToolDependencies,
): void {
  server.registerTool(
    'delegate-credential',
    {
      description:
        'Delegate a credential to another agent with a narrower scope. The delegated scope must be a subset of the source credential.',
      inputSchema: {
        sourceAgentDid: z.string().describe('DID of the agent that holds the source credential'),
        sourceCredential: z.string().describe('JWT of the source credential to delegate from'),
        targetAgent: z.string().describe('DID of the agent receiving the delegated credential'),
        columns: z.array(z.string()).describe('Columns to grant (must be subset of source)'),
        actions: z.array(z.string()).describe('Actions to grant (must be subset of source)'),
        expiresIn: z
          .union([z.string(), z.number()])
          .describe('Duration string ("1h", "30m") or seconds'),
      },
    },
    async ({ sourceAgentDid, sourceCredential, targetAgent, columns, actions, expiresIn }) => {
      try {
        if (deps.credentialMaxTtlMs !== undefined) {
          assertExpiresInBound(expiresIn, deps.credentialMaxTtlMs);
        }
        assertWithinMintQuota(deps);
        const { credential } = await deps.services.credentials.delegateCredential(
          {
            sourceAgentDid,
            sourceCredential,
            targetAgent,
            columns,
            actions,
            expiresIn,
          },
          { scopeCeiling: deps.session.scopeCeiling },
        );
        return {
          content: [{ type: 'text' as const, text: JSON.stringify({ credential }) }],
        };
      } catch (err) {
        return mapAgentScopeError(err, deps.logger);
      }
    },
  );
}
