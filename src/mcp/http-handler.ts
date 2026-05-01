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
 * MCP HTTP transport request handler — per-connection session routing.
 *
 * Owns the `Map<sessionId, SSEServerTransport>` so concurrent SSE clients
 * never cross routes. Keyed by the SDK-generated UUID surfaced in each
 * transport's `endpoint` event. Single-human-DID per process is enforced
 * by the bootstrap; this layer is the routing fix for CWE-384/CWE-863.
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { McpBearerAuth } from './auth.js';

export interface McpHttpHandlerOptions {
  mcpServer: McpServer;
  bearerGuard: McpBearerAuth | null;
  log: (...args: unknown[]) => void;
  /**
   * Soft cap on concurrent /sse sessions. Returns 503 when exceeded so a
   * misbehaving client (or compromised bearer holder) cannot indefinitely
   * accumulate transports. Default 100. Idle-session reaping is deferred
   * to a follow-up; cleanup still runs on response close / transport close.
   */
  maxConcurrentSessions?: number;
  /**
   * When true, a second GET /sse while one session is open returns 409 Conflict.
   * Matches the documented "one process = one human session" deployment model.
   * Default false (permits multiple concurrent sessions, e.g. CLI + IDE under the same human DID).
   */
  singleSessionMode?: boolean;
}

export interface McpHttpHandler {
  /** Express-style request handler: route, authenticate, dispatch. */
  handle(req: IncomingMessage, res: ServerResponse): void;
  /** Number of currently open SSE sessions (test/diagnostics). */
  activeSessionCount(): number;
  /** Close every open SSE transport before shutting down. */
  closeAll(): Promise<void>;
}

const DEFAULT_MAX_CONCURRENT_SESSIONS = 100;

const BASELINE_HEADERS: ReadonlyArray<[string, string]> = [
  ['X-Content-Type-Options', 'nosniff'],
  ['Cache-Control', 'no-store'],
  ['Referrer-Policy', 'no-referrer'],
  ['Cross-Origin-Resource-Policy', 'same-origin'],
];

function setSecurityHeaders(req: IncomingMessage, res: ServerResponse): void {
  for (const [name, value] of BASELINE_HEADERS) {
    res.setHeader(name, value);
  }
  if ((req.socket as unknown as { encrypted?: boolean })?.encrypted) {
    res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains');
  }
}

export function createMcpHttpHandler(options: McpHttpHandlerOptions): McpHttpHandler {
  const { mcpServer, bearerGuard } = options;
  const maxSessions = options.maxConcurrentSessions ?? DEFAULT_MAX_CONCURRENT_SESSIONS;
  const singleSession = options.singleSessionMode ?? false;
  const transports = new Map<string, SSEServerTransport>();

  function handle(req: IncomingMessage, res: ServerResponse): void {
    setSecurityHeaders(req, res);
    let pathname: string;
    let searchParams: URLSearchParams;
    try {
      // Fixed base URL — req.headers.host is attacker-controlled (SSRF seed).
      const u = new URL(req.url ?? '/', 'http://localhost');
      pathname = u.pathname;
      searchParams = u.searchParams;
    } catch {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'invalid_request', code: 400 }));
      return;
    }

    if (pathname === '/health') {
      res.writeHead(200);
      res.end('ok');
      return;
    }

    if (bearerGuard && !bearerGuard.httpGuard(req, res)) return;

    if (pathname === '/sse') {
      if (singleSession && transports.size >= 1) {
        res.writeHead(409, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'session_conflict', code: 409 }));
        return;
      }
      if (transports.size >= maxSessions) {
        res.writeHead(503, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'too_many_sessions', code: 503 }));
        return;
      }
      const transport = new SSEServerTransport('/messages', res);
      const sessionId = transport.sessionId;
      transports.set(sessionId, transport);
      const cleanup = () => {
        transports.delete(sessionId);
      };
      res.on('close', cleanup);
      transport.onclose = cleanup;
      void mcpServer.connect(transport).catch(cleanup);
      return;
    }

    if (pathname === '/messages' && req.method === 'POST') {
      const sessionId = searchParams.get('sessionId');
      if (!sessionId) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'invalid_session', code: 400 }));
        return;
      }
      const transport = transports.get(sessionId);
      if (!transport) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'invalid_session', code: 400 }));
        return;
      }
      void transport.handlePostMessage(req, res);
      return;
    }

    res.writeHead(404);
    res.end('Not found');
  }

  function activeSessionCount(): number {
    return transports.size;
  }

  async function closeAll(): Promise<void> {
    const list = Array.from(transports.values());
    // Each t.close() fires onclose → cleanup → transports.delete; no need
    // to clear the map up front. Best-effort close: if a transport throws
    // (already closed by the client, broken pipe, etc.) we still want the
    // others to close.
    await Promise.all(list.map((t) => t.close().catch(() => undefined)));
  }

  return { handle, activeSessionCount, closeAll };
}
