#!/usr/bin/env node
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
 * MCP Server Entry Point — parse CLI args, initialize AgentScope, start server.
 *
 * Usage: agents mcp --db <url> [--mock <name>] [--tls-cert <path> --tls-key <path>] [--insecure] [--allow-no-auth] [--single-instance]
 *
 * Boot order: TrustAnchorStore must be loaded before MCP accepts connections.
 * Any incoming request before the store is loaded will be rejected by AgentVerifier (fail-closed),
 * not silently served with an empty trust list. This is enforced by AgentScope.create() awaiting
 * TrustAnchorStore.load() before returning.
 */

import { readFileSync } from 'node:fs';
import https from 'node:https';
import http from 'node:http';
import { resolveMasterKeyFromEnv } from '#bootstrap/index.js';
import type { Logger } from '#observability/logger.js';
import { getLogger } from '#observability/logger.js';
import type { StorageBackend } from '#storage/types.js';
import { createMcpServer, connectStdio } from './server.js';
import { createMcpBearerAuth, type McpBearerAuth } from './auth.js';
import { createMcpHttpHandler } from './http-handler.js';
import {
  evaluateMcpHttpBearerBoot,
  resolveMcpHttpBearerTokenCount,
  type McpHttpBearerResolution,
} from './http-bearer-boot.js';

export { createMcpServer } from './server.js';
export type { McpServerOptions } from './server.js';

export interface McpCliOptions {
  db: string;
  mock?: string;
  transport?: 'stdio' | 'http';
  port?: number;
  tlsCert?: string;
  tlsKey?: string;
  insecure?: boolean;
  singleInstance?: boolean;
  /**
   * Opt in to HTTP transport with no bearer tokens (development/test only).
   * Ignored for stdio. Without this flag, HTTP refuses to start if bearerAuth is
   * missing or getValidTokens() yields no usable tokens.
   */
  allowNoAuth?: boolean;
  /**
   * Bearer auth config for HTTP transport.
   *
   * When provided, every HTTP request to /sse and /messages must carry a valid
   * Authorization: Bearer <token> header. Requests without a valid token receive
   * a 401 JSON response before the MCP SDK processes them.
   *
   * Ignored for stdio transport (trusted local pipe).
   */
  bearerAuth?: { getValidTokens: () => string[] };
  /** Optional diagnostic logger. Defaults to stderr. */
  logger?: Logger;
  /** Pre-built `StorageBackend`. When provided, the production refusal gate and coherency warning are skipped. */
  storage?: StorageBackend;
}

type AgentScopeConstructor = (typeof import('#sql/index.js'))['AgentScope'];

function isMissingPeerDependencyError(err: unknown): boolean {
  const message = err instanceof Error ? err.message : String(err);
  return (
    message.includes("Cannot find package 'pg'") ||
    message.includes('Cannot find package "pg"') ||
    message.includes("Cannot find package 'libpg-query'") ||
    message.includes('Cannot find package "libpg-query"') ||
    message.includes("Cannot find module 'pg'") ||
    message.includes('Cannot find module "pg"') ||
    message.includes("Cannot find module 'libpg-query'") ||
    message.includes('Cannot find module "libpg-query"')
  );
}

function assertMcpHttpBearerAuthOrExit(
  options: McpCliOptions,
  log: (...args: unknown[]) => void,
  resolution: McpHttpBearerResolution,
): void {
  const result = evaluateMcpHttpBearerBoot(options, process.env.NODE_ENV, resolution);
  if (result.action === 'ok') return;
  if (result.action === 'warn_no_auth') {
    for (const line of result.stderrLines) log(line.replace(/^\[agents\]\s*/, ''));
    return;
  }
  for (const line of result.stderrLines) log(line);
  process.exit(result.code);
}

async function loadAgentScope(): Promise<AgentScopeConstructor> {
  try {
    return (await import('#sql/index.js')).AgentScope;
  } catch (err) {
    if (isMissingPeerDependencyError(err)) {
      const message = err instanceof Error ? err.message : String(err);
      throw new Error(
        'startMcpServer requires the SQL peer dependencies "pg" and "libpg-query". ' +
          'Install the documented dependency set: npm install pg@8.20.0 libpg-query@17.7.3\n' +
          `Original error: ${message}`,
      );
    }
    throw err;
  }
}

export async function startMcpServer(options: McpCliOptions): Promise<void> {
  const {
    db,
    mock,
    transport = 'stdio',
    port = 8080,
    tlsCert,
    tlsKey,
    insecure,
    singleInstance,
    storage,
  } = options;

  // Use stderr for all logging — stdout is reserved for MCP JSON-RPC in stdio mode
  const mcpLogger = getLogger(options.logger);
  const log = (...args: unknown[]) => mcpLogger.error('[agents] ' + args.map(String).join(' '));

  // Default-storage MCP refuses to start in production unless the operator acknowledges
  // single-instance deployment. The default PostgresStorageBackend has revocation coherency
  // poll OFF, so a revoked credential remains valid on N-1 of N peers until restart.
  if (process.env.NODE_ENV === 'production' && !storage) {
    if (!singleInstance) {
      mcpLogger.error(
        '[agents] Refusing to start: NODE_ENV=production with default storage. ' +
          'The default PostgresStorageBackend has revocation coherency poll OFF, which is unsafe ' +
          'for multi-instance deployments. Either inject an explicit StorageBackend with the ' +
          'coherency poll enabled (via direct AgentScope.create), or pass --single-instance to ' +
          'acknowledge a single-instance deployment.',
      );
      process.exit(1);
    }
    log('Single-instance mode acknowledged (--single-instance).');
    log(
      'WARNING: MCP server booting in NODE_ENV=production without an explicit storage injection. ' +
        'The library will build a default PostgresStorageBackend with cross-instance revocation ' +
        'coherency poll OFF — revocations propagated from peer instances will NOT be visible until ' +
        'next process restart. Acceptable for single-instance MCP; NOT acceptable for multi-instance ' +
        'deployments. To run multi-instance, construct an explicit StorageBackend (with the coherency ' +
        'poll enabled) and pass it via injections — see docs/support-runbook-v0.9.10.0.md § ' +
        '"MCP multi-instance revocation coherency".',
    );
  }

  // Computed once during the HTTP boot gate, then reused when wiring bearerGuard
  // below (avoids redundant getValidTokens() on every start).
  let bearerResolution: McpHttpBearerResolution | undefined;

  if (transport === 'http') {
    const env = (process.env.NODE_ENV ?? '').toLowerCase();

    if (insecure) {
      if (env !== 'development' && env !== 'test') {
        mcpLogger.error('[agents] --insecure requires NODE_ENV=development or NODE_ENV=test');
        process.exit(1);
      }
      log('WARNING: Running HTTP without TLS (--insecure). Do not use in production.');
    } else if (!tlsCert || !tlsKey) {
      mcpLogger.error(
        '[agents] HTTP transport requires --tls-cert and --tls-key, or --insecure for local dev',
      );
      process.exit(1);
    }

    bearerResolution = resolveMcpHttpBearerTokenCount(options);
    assertMcpHttpBearerAuthOrExit(options, log, bearerResolution);
  }

  log('Connecting to database...');
  const AgentScopeCtor = await loadAgentScope();
  const masterKey = resolveMasterKeyFromEnv();
  const nodeEnv = process.env.NODE_ENV;
  const devMode =
    process.env.AGENTS_DEV_MODE === 'true' || nodeEnv === 'development' || nodeEnv === 'test';

  // Freeze to ensure both AgentScope and any GenericOidcProvider use the same array.
  const extraConsumerDomains = Object.freeze(
    (process.env.AGENTS_CONSUMER_DOMAINS ?? '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
  );
  const scope = await AgentScopeCtor.create(
    {
      database: { connectionString: db },
      abaxxOne: { tenantUrl: 'https://one.abaxx.tech', clientId: 'agents-mcp' },
      ...(devMode && { devMode: true }),
      ...(extraConsumerDomains.length > 0 && {
        orgBoundary: { extraConsumerDomains },
      }),
    },
    { masterKey, logger: mcpLogger, ...(storage && { storage }) },
  );

  log('Authenticating session...');
  const session = mock
    ? await scope.authenticate({ mockHumanDid: mock })
    : await scope.authenticate();

  log(`Session authenticated as ${session.humanDid}`);

  const mcpServer = createMcpServer({
    scope,
    session,
    auditLogger: scope.auditLoggerInstance,
    logger: mcpLogger,
    credentialMaxTtlMs: scope.credentialMaxTtlMs,
  });

  if (transport === 'stdio') {
    log('MCP server starting on stdio...');
    await connectStdio(mcpServer);
    log('MCP server running on stdio');
  } else {
    // bearerResolution was computed and validated by the boot gate above.
    const bearerGuard: McpBearerAuth | null =
      bearerResolution?.ok && options.bearerAuth
        ? createMcpBearerAuth(options.bearerAuth)
        : null;

    const httpHandler = createMcpHttpHandler({ mcpServer, bearerGuard, log });
    const handler = httpHandler.handle;

    let server: http.Server | https.Server;
    const bindHost = tlsCert && tlsKey ? '0.0.0.0' : '127.0.0.1';

    if (tlsCert && tlsKey) {
      server = https.createServer(
        {
          cert: readFileSync(tlsCert),
          key: readFileSync(tlsKey),
        },
        handler,
      );
      log(`MCP server starting on HTTPS port ${port}...`);
    } else {
      // Insecure mode — loopback only
      server = http.createServer(handler);
      log(`MCP server starting on HTTP ${bindHost}:${port} (insecure)...`);
    }

    server.listen(port, bindHost, () => {
      const proto = tlsCert ? 'https' : 'http';
      log(`MCP server running at ${proto}://${bindHost}:${port}`);
    });

    let shuttingDown = false;
    const shutdown = async () => {
      if (shuttingDown) return;
      shuttingDown = true;
      log('Shutting down...');
      await httpHandler.closeAll();
      server.close();
      await scope.close();
      process.exit(0);
    };

    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);
  }
}
