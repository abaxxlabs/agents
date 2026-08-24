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

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { AgentScope } from '#sql/index.js';
import type { AuthenticatedSession } from '#types/auth.js';
import type { AuditLogger } from '#audit/index.js';
import type { ServerIdentity } from '#identity/index.js';
import type { TrustAnchorStore } from '#discovery/trust-anchor.js';
import { createAgentToolServices, type AgentToolServices } from '#services/index.js';
import type { Logger } from '#observability/logger.js';
import { getLogger } from '#observability/logger.js';
import type { RateLimiter } from '#transport/index.js';
import { ChallengeStore } from './challenge-store.js';
import { registerQueryTool } from './query-tools.js';
import { registerCreateAgentTool, registerListAgentsTool } from './agent-tools.js';
import {
  registerDelegateCredentialTool,
  registerIssueCredentialTool,
  registerRevokeCredentialTool,
} from './credential-tools.js';
import {
  registerExportAuditTool,
  registerVerifyAuditTool,
  registerVerifyChainTool,
} from './audit-tools.js';
import { registerIdentityTools } from './identity-tools.js';

/**
 * Session-bound inputs for MCP tool registration.
 *
 * - `serverIdentity` (with `trustAnchorStore`) enables identity tools when provided;
 *   the identity tools are not registered otherwise.
 * - `challengeStore` backs the `challenge` tool.
 * - `rateLimiter` is shared by the credential, sign, and challenge tools. Quotas are
 *   always keyed by human DID so another session cannot reset them.
 * - `bindingVcJwt`, `bindingExpiry` (Unix timestamp seconds) and `orgDomain` feed the
 *   `whoami` tool; `orgDomain` is null for consumer accounts.
 * - `credentialMaxTtlMs` bounds `expiresIn` checks (parsed `credential.maxTtl`).
 */
export interface ToolDependencies {
  session: AuthenticatedSession;
  services?: AgentToolServices;
  logger?: Logger;
  serverIdentity?: ServerIdentity;
  trustAnchorStore?: TrustAnchorStore;
  challengeStore?: ChallengeStore;
  rateLimiter?: RateLimiter;
  /**
   * @deprecated Ignored since 0.16.0, removed in 1.0.0. Passing it throws.
   * Quotas are keyed by `session.humanDid` so another session cannot reset them;
   * a caller-supplied principal reintroduced that bypass.
   */
  rateLimitPrincipal?: never;
  bindingVcJwt?: string;
  bindingExpiry?: number;
  orgDomain?: string | null;
  credentialMaxTtlMs?: number;
}

export type ToolServiceFallbackDependencies = {
  scope?: AgentScope;
  auditLogger?: AuditLogger;
};

export function resolveServices(
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
    statusReader: deps.scope,
  });
}

export function registerTools(
  server: McpServer,
  deps: ToolDependencies & ToolServiceFallbackDependencies,
): void {
  // Fail loudly: silently ignoring it would leave callers believing their quota
  // is keyed by the value they passed.
  if ((deps as { rateLimitPrincipal?: unknown }).rateLimitPrincipal !== undefined) {
    throw new Error(
      'rateLimitPrincipal was removed. Rate-limit quotas are keyed by session.humanDid; delete the option.',
    );
  }

  const services = resolveServices(deps);
  const logger = getLogger(deps.logger);
  const core = { services, session: deps.session, logger };
  const credentials = {
    ...core,
    credentialMaxTtlMs: deps.credentialMaxTtlMs,
    rateLimiter: deps.rateLimiter,
  };

  registerQueryTool(server, core);
  registerCreateAgentTool(server, core);
  registerIssueCredentialTool(server, credentials);
  registerRevokeCredentialTool(server, credentials);
  registerDelegateCredentialTool(server, credentials);
  registerVerifyAuditTool(server, core);
  registerExportAuditTool(server, core);
  registerListAgentsTool(server, core);
  registerVerifyChainTool(server, core);

  if (!deps.serverIdentity) return;
  registerIdentityTools(
    server,
    {
      session: deps.session,
      trustAnchorStore: deps.trustAnchorStore,
      challengeStore: deps.challengeStore,
      rateLimiter: deps.rateLimiter,
      bindingSource: deps,
      logger,
    },
    deps.serverIdentity,
  );
}
