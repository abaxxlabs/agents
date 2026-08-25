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
 * PostgreSQL backend composing all stores over the pool shared with ScopeEngine.
 */

import pg from 'pg';
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import type {
  StorageBackend,
  PostgresStorageOptions,
  AgentStore,
  AuditStore,
  ContextStore,
  RevocationStore,
  SessionStore,
} from '../types.js';
import { PostgresAgentStore } from './agent-store.js';
import { PostgresAuditStore } from './audit-store.js';
import { PostgresContextStore } from './context-store.js';
import { PostgresRevocationStore } from './revocation-store.js';
import type { PostgresRevocationStoreOptions } from './revocation-store.js';
import { PostgresSessionStore } from './session-store.js';
import type { PostgresSessionStoreOptions } from './session-store.js';
import type { Logger } from '#observability/logger.js';
import { getLogger } from '#observability/logger.js';

const { Pool } = pg;

/**
 * Postgres-specific sub-store options. `sessionMacKey` is required for
 * cross-process MAC verification. Derive via `deriveSessionMacKey()`.
 */
export interface PostgresStorageBackendExtraOptions {
  revocationOptions?: PostgresRevocationStoreOptions;
  sessionMacKey: Buffer;
  sessionStoreOptions?: PostgresSessionStoreOptions;
  /** Optional diagnostic logger. */
  logger?: Logger;
}

export class PostgresStorageBackend implements StorageBackend {
  private readonly _pool: pg.Pool;
  private readonly _agents: PostgresAgentStore;
  private readonly _audit: PostgresAuditStore;
  private readonly _context: PostgresContextStore;
  private readonly _revocation: PostgresRevocationStore;
  private readonly _sessions: PostgresSessionStore;
  private readonly _logger: Logger;
  private _ownsPool = true;
  private _closed = false;

  constructor(options: PostgresStorageOptions, extraOptions?: PostgresStorageBackendExtraOptions) {
    if (!extraOptions?.sessionMacKey) {
      throw new TypeError(
        'PostgresStorageBackend requires a sessionMacKey. ' +
          'Derive one via deriveSessionMacKey(masterKey) from @abaxxlabs/agents.',
      );
    }
    this._logger = getLogger(extraOptions.logger);
    this._pool = new Pool({
      connectionString: options.connectionString,
      max: options.poolSize ?? 10,
    });

    const macKey = extraOptions.sessionMacKey;

    this._agents = new PostgresAgentStore(this._pool);
    this._audit = new PostgresAuditStore(this._pool);
    this._context = new PostgresContextStore(this._pool);
    this._revocation = new PostgresRevocationStore(
      this._pool,
      extraOptions?.revocationOptions,
      this._logger,
    );
    this._sessions = new PostgresSessionStore(
      this._pool,
      macKey,
      extraOptions?.sessionStoreOptions,
    );
  }

  /**
   * Wraps an existing pool without taking ownership by default.
   * @param pool Existing PostgreSQL pool.
   * @param ownsPool Whether close() also closes the pool.
   * @param extraOptions Store-specific configuration.
   */
  static fromPool(
    pool: pg.Pool,
    ownsPool = false,
    extraOptions?: PostgresStorageBackendExtraOptions,
  ): PostgresStorageBackend {
    if (!extraOptions?.sessionMacKey) {
      throw new TypeError(
        'PostgresStorageBackend.fromPool() requires a sessionMacKey. ' +
          'Derive one via deriveSessionMacKey(masterKey) from @abaxxlabs/agents.',
      );
    }
    const backend = Object.create(PostgresStorageBackend.prototype) as PostgresStorageBackend;
    const macKey = extraOptions.sessionMacKey;
    const logger = getLogger(extraOptions.logger);
    const mut = backend as unknown as {
      _pool: pg.Pool;
      _agents: PostgresAgentStore;
      _audit: PostgresAuditStore;
      _context: PostgresContextStore;
      _revocation: PostgresRevocationStore;
      _sessions: PostgresSessionStore;
      _logger: Logger;
      _ownsPool: boolean;
      _closed: boolean;
    };
    mut._pool = pool;
    mut._logger = logger;
    mut._agents = new PostgresAgentStore(pool);
    mut._audit = new PostgresAuditStore(pool);
    mut._context = new PostgresContextStore(pool);
    mut._revocation = new PostgresRevocationStore(pool, extraOptions?.revocationOptions, logger);
    mut._sessions = new PostgresSessionStore(pool, macKey, extraOptions?.sessionStoreOptions);
    mut._ownsPool = ownsPool;
    mut._closed = false;
    return backend;
  }

  get agents(): AgentStore {
    return this._agents;
  }
  get audit(): AuditStore {
    return this._audit;
  }
  get context(): ContextStore {
    return this._context;
  }
  get revocation(): RevocationStore {
    return this._revocation;
  }
  get sessions(): SessionStore {
    return this._sessions;
  }

  /**
   * Exposes the pool for ScopeEngine and column encryption data queries.
   */
  get pool(): pg.Pool {
    return this._pool;
  }

  /** Tests connectivity, applies ordered SQL migrations when a migrations directory is available, and starts revocation coherency. */
  async initialize(): Promise<void> {
    await this._pool.query('SELECT 1');

    const migrationsDir = this._findMigrationsDir();
    if (migrationsDir) {
      const files = readdirSync(migrationsDir)
        .filter((f) => f.endsWith('.sql'))
        .sort(); // Migration filenames use zero-padded lexical ordering.

      for (const file of files) {
        try {
          const sql = readFileSync(join(migrationsDir, file), 'utf8');
          await this._pool.query(sql);
        } catch (err) {
          this._logger.error(`[storage] Migration failed: ${file}`, { file, error: err });
          throw err;
        }
      }
    }

    try {
      await this._revocation.loadAll();
    } catch (err) {
      this._logger.warn('[storage] Revocation cache warm-up failed (cold cache)', { error: err });
    }
    this._revocation.startCoherency();
  }

  /** Idempotently stops polling and closes an owned pool. */
  async close(): Promise<void> {
    if (this._closed) return;
    this._closed = true;
    this._revocation.stopCoherency();
    if (!this._ownsPool) return;
    await this._pool.end();
  }

  /**
   * Locates migrations across CJS, ESM, and source layouts.
   * @returns Null when no candidate directory exists.
   */
  private _findMigrationsDir(): string | null {
    let moduleDir: string | null = null;
    if (typeof __dirname !== 'undefined') {
      moduleDir = __dirname;
    }
    if (!moduleDir) {
      try {
        const metaUrl: string | undefined =
          (0, eval)('typeof import.meta !== "undefined" && import.meta.url') || undefined;
        if (metaUrl) {
          moduleDir = dirname(fileURLToPath(metaUrl));
        }
      } catch (err) {
        this._logger.error('[storage] Failed to resolve migrations from import.meta', {
          error: err,
        });
      }
    }

    const candidates: string[] = [];
    if (moduleDir) {
      candidates.push(
        join(moduleDir, '..', '..', '..', 'migrations'), // from src/ or dist/
        join(moduleDir, '..', '..', '..', '..', 'migrations'), // from dist/cjs/
      );
    }
    candidates.push(join(process.cwd(), 'migrations')); // fallback: project root

    for (const dir of candidates) {
      try {
        readdirSync(dir);
        return dir;
      } catch {
        continue;
      }
    }
    return null;
  }
}
