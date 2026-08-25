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
import type { AuthenticatedSession } from '#types/auth.js';
import type { ServerIdentity } from '#identity/index.js';
import type { TrustAnchorStore } from '#discovery/trust-anchor.js';
import type { Logger } from '#observability/logger.js';
import { ChallengeStore } from './challenge-store.js';
import {
  CHALLENGE_RATE_LIMIT,
  CHALLENGE_RATE_WINDOW_MS,
  SIGN_PAYLOAD_MAX_BYTES,
  SIGN_RATE_LIMIT,
  SIGN_RATE_WINDOW_MS,
  assertUtf8MaxBytes,
  assertWithinRateLimit,
  defaultIdentityRateLimiter,
  mcpToolInputShapes,
  type RateLimiter,
} from '#transport/index.js';
import { mapAgentScopeError } from './tool-errors.js';

interface IdentityToolDependencies {
  session: AuthenticatedSession;
  trustAnchorStore?: TrustAnchorStore;
  challengeStore?: ChallengeStore;
  rateLimiter?: RateLimiter;
  bindingSource: {
    bindingVcJwt?: string;
    bindingExpiry?: number;
    orgDomain?: string | null;
  };
  logger?: Logger;
}

export function registerIdentityTools(
  server: McpServer,
  deps: IdentityToolDependencies,
  serverIdentity: ServerIdentity,
): void {
  const challengeStore = deps.challengeStore ?? new ChallengeStore();
  const rateLimiter = deps.rateLimiter ?? defaultIdentityRateLimiter;
  const rateLimitPrincipal = deps.session.humanDid;

  server.registerTool(
    'whoami',
    {
      description:
        'Return the current server identity bundle: server DID, human DID, org domain, binding credential, and DID method.',
      inputSchema: {},
    },
    async () => {
      try {
        return {
          content: [
            {
              type: 'text' as const,
              text: JSON.stringify({
                serverDid: serverIdentity.did,
                humanDid: deps.session.humanDid,
                orgDomain: deps.bindingSource.orgDomain ?? null,
                bindingVcJwt: deps.bindingSource.bindingVcJwt ?? null,
                bindingExpiry: deps.bindingSource.bindingExpiry ?? null,
                currentDidMethod: 'did:key' as const,
              }),
            },
          ],
        };
      } catch (err) {
        return mapAgentScopeError(err, deps.logger);
      }
    },
  );

  server.registerTool(
    'sign',
    {
      description:
        "Sign an arbitrary payload with the server's Ed25519 key. Returns a JWT containing the domain-separated payload. Max 64KB payload.",
      inputSchema: mcpToolInputShapes.sign,
    },
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

        const jwt = await serverIdentity.signer.signJwt({
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
        return mapAgentScopeError(err, deps.logger);
      }
    },
  );

  server.registerTool(
    'discover',
    {
      description:
        'List trusted server DIDs and the current identity topology. Shows the trust boundary this server recognizes.',
      inputSchema: {},
    },
    async () => {
      try {
        return {
          content: [
            {
              type: 'text' as const,
              text: JSON.stringify({
                serverDid: serverIdentity.did,
                trustedAnchors: deps.trustAnchorStore?.list() ?? [],
                didMethod: 'did:key' as const,
              }),
            },
          ],
        };
      } catch (err) {
        return mapAgentScopeError(err, deps.logger);
      }
    },
  );

  // consume() stays server-side so callers cannot verify their own challenges.
  server.registerTool(
    'challenge',
    {
      description:
        'Issue a time-bound challenge for VP (Verifiable Presentation) requests. The challenge must be included in the VP to prove freshness.',
      inputSchema: mcpToolInputShapes.challenge,
    },
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
        return mapAgentScopeError(err, deps.logger);
      }
    },
  );
}
