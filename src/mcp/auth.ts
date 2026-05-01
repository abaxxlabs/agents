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
 * MCP Bearer Auth — session token authentication for MCP HTTP transport.
 *
 * Enforced at the HTTP transport layer before the MCP SDK sees any request.
 * Stdio transport has no bearer auth (trusted local pipe).
 * Token comparison uses timingSafeEqual to prevent timing side-channels.
 * getValidTokens() returns an array to support overlap during token rotation.
 */

import { timingSafeEqual } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';

// ─── Constants ───────────────────────────────────────────────────────────────

/** How long an old token stays valid alongside a new one during rotation. */
export const OVERLAP_WINDOW_SECONDS = 30;

// ─── Types ───────────────────────────────────────────────────────────────────

/**
 * Options for creating a bearer auth guard.
 *
 * getValidTokens returns the set of currently valid bearer tokens. The array
 * supports rotation: typically [currentToken] during steady state, and
 * [newToken, oldToken] during the OVERLAP_WINDOW_SECONDS rotation period.
 *
 * The callback is invoked on every HTTP request — it must be fast (O(n) where
 * n is token count, typically 1-2). No async, no I/O.
 */
export interface McpBearerAuthOptions {
  getValidTokens: () => string[];
}

/**
 * Bearer auth guard — the public interface for MCP HTTP authentication.
 *
 * Three methods cover the full auth flow:
 *   extractToken — pull the bearer token from the HTTP Authorization header
 *   validateToken — check a token string against the current valid set
 *   httpGuard — combined extract+validate+respond for HTTP handler use
 */
export interface McpBearerAuth {
  /**
   * Extract the bearer token from an HTTP request's Authorization header.
   *
   * Accepts only the standard format: `Authorization: Bearer <token>`.
   * Returns undefined if the header is missing, malformed, or uses a
   * different auth scheme (e.g., Basic).
   */
  extractToken(req: IncomingMessage): string | undefined;

  /**
   * Validate a token string against the current set of valid tokens.
   *
   * Uses constant-time comparison to prevent timing side-channels.
   * Returns true if the token matches any entry in getValidTokens().
   * Returns false for undefined, empty string, or non-matching tokens.
   */
  validateToken(token: string | undefined): boolean;

  /**
   * HTTP guard — extract, validate, and respond in one call.
   *
   * Returns true if the request is authorized (caller should proceed).
   * Returns false if unauthorized (401 response already sent — caller
   * should NOT send any further response).
   *
   * Usage in HTTP handler:
   *   if (!bearerAuth.httpGuard(req, res)) return;
   *   // ... proceed with authorized request
   */
  httpGuard(req: IncomingMessage, res: ServerResponse): boolean;
}

// ─── Implementation ──────────────────────────────────────────────────────────

/**
 * Constant-time string comparison. When lengths differ, compares against a
 * zero buffer to prevent length-based timing leaks (always fails, constant time).
 */
function constantTimeEquals(a: string, b: string): boolean {
  const aBuf = Buffer.from(a, 'utf-8');
  const bBuf = Buffer.from(b, 'utf-8');

  if (aBuf.length !== bBuf.length) {
    const dummy = Buffer.alloc(bBuf.length); // always fails, but constant time
    timingSafeEqual(dummy, bBuf);
    return false;
  }

  return timingSafeEqual(aBuf, bBuf);
}

/**
 * Create a bearer auth guard for MCP HTTP transport.
 *
 * The returned object is stateless — it calls getValidTokens() on every
 * validation. Token rotation is managed externally (typically by the binding
 * refresh lifecycle in ServerIdentity or the session manager).
 *
 * @example
 *   const auth = createMcpBearerAuth({
 *     getValidTokens: () => sessionManager.getActiveTokens(),
 *   });
 *
 *   // In HTTP handler:
 *   const handler = (req, res) => {
 *     if (!auth.httpGuard(req, res)) return;  // 401 already sent
 *     // ... handle authenticated request
 *   };
 */
export function createMcpBearerAuth(options: McpBearerAuthOptions): McpBearerAuth {
  const { getValidTokens } = options;

  function extractToken(req: IncomingMessage): string | undefined {
    const authHeader = req.headers.authorization;
    if (!authHeader || typeof authHeader !== 'string') return undefined;

    // RFC 6750: The access token is sent in the Authorization header using
    // the Bearer scheme. We enforce case-insensitive "Bearer" prefix and
    // require at least one character after the space.
    const match = authHeader.match(/^Bearer\s+(\S+)$/i);
    return match?.[1];
  }

  function validateToken(token: string | undefined): boolean {
    // Reject falsy values and non-string types. The typeof check defends
    // against callers passing a number or object from untyped contexts
    // (e.g., parsed JSON query params). Without this, Buffer.from() in
    // constantTimeEquals throws on non-string input.
    if (!token || typeof token !== 'string') return false;

    const validTokens = getValidTokens();
    for (const valid of validTokens) {
      if (constantTimeEquals(valid, token)) return true;
    }
    return false;
  }

  function httpGuard(req: IncomingMessage, res: ServerResponse): boolean {
    const token = extractToken(req);
    if (validateToken(token)) return true;

    // 401: no token hints or count in the response (oracle prevention).
    res.writeHead(401, {
      'Content-Type': 'application/json',
      'WWW-Authenticate': 'Bearer realm="agents-mcp"', // RFC 6750 §3
    });
    res.end(JSON.stringify({ error: 'unauthorized', code: 401 }));
    return false;
  }

  return { extractToken, validateToken, httpGuard };
}
