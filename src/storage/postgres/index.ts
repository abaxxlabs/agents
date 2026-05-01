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
 * Postgres implementation of StorageBackend. Composes all five sub-stores over
 * a shared pg.Pool. Pool is exposed via the `pool` getter so ScopeEngine can
 * share it without creating a second connection to the same database.
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
import type { Logger } from '../../logger.js';
import { defaultLogger } from '../../logger.js';

const { Pool } = pg;

/**
 * Postgres-specific sub-store options. `sessionMacKey` must be supplied for
 * cross-process MAC verification; defaults to a 32-byte zero buffer (tests only).
 * Derive via `deriveSessionMacKey()` for production.
 */
export interface PostgresStorageBackendExtraOptions {
  revocationOptions?: PostgresRevocationStoreOptions;
  sessionMacKey?: Buffer;
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
  /** Whether this backend owns the pool lifecycle (close() calls pool.end()). */
  private _ownsPool = true;
  /** Guard against double-close. */
  private _closed = false;

  constructor(options: PostgresStorageOptions, extraOptions?: PostgresStorageBackendExtraOptions) {
    this._logger = extraOptions?.logger ?? defaultLogger;
    this._pool = new Pool({
      connectionString: options.connectionString,
      max: options.poolSize ?? 10,
    });

    const macKey = extraOptions?.sessionMacKey ?? Buffer.alloc(32, 0);

    this._agents = new PostgresAgentStore(this._pool);
    this._audit = new PostgresAuditStore(this._pool);
    this._context = new PostgresContextStore(this._pool);
    this._revocation = new PostgresRevocationStore(this._pool, extraOptions?.revocationOptions, this._logger);
    this._sessions = new PostgresSessionStore(
      this._pool,
      macKey,
      extraOptions?.sessionStoreOptions,
    );
  }

  /**
   * Construct a PostgresStorageBackend from an existing pg.Pool.
   *
   * Used by AgentScope for backward compatibility — when the Pool is already
   * created from database.connectionString, we wrap it rather than creating
   * a second pool. The caller retains ownership of the Pool's lifecycle.
   *
   * @param pool — existing pg.Pool (caller owns lifecycle).
   * @param ownsPool — if false, close() will NOT end the pool. Default: false.
   * @param extraOptions — optional sub-store config (revocation coherency,
   *   session MAC key, session cache).
   */
  static fromPool(
    pool: pg.Pool,
    ownsPool = false,
    extraOptions?: PostgresStorageBackendExtraOptions,
  ): PostgresStorageBackend {
    const backend = Object.create(PostgresStorageBackend.prototype) as PostgresStorageBackend;
    const macKey = extraOptions?.sessionMacKey ?? Buffer.alloc(32, 0);
    const logger = extraOptions?.logger ?? defaultLogger;
    // Bypass readonly to populate the prototype-created instance from an externally-owned pool.
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

  // ─── Sub-stores ─────────────────────────────────────────────────────────────

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
   * Expose the underlying pg.Pool for ScopeEngine and column encryption.
   *
   * These modules query the user's data tables (not agents metadata), so they
   * operate outside the StorageBackend abstraction. Sharing the pool avoids
   * creating duplicate connections to the same database.
   */
  get pool(): pg.Pool {
    return this._pool;
  }

  // ─── Lifecycle ──────────────────────────────────────────────────────────────

  /** Test connection and run migrations. Idempotent (CREATE TABLE IF NOT EXISTS). */
  async initialize(): Promise<void> {
    // Test connection
    await this._pool.query('SELECT 1');

    // Run migration files in order.
    // Missing migrations directory is handled by _findMigrationsDir() returning null.
    const migrationsDir = this._findMigrationsDir();
    if (migrationsDir) {
      const files = readdirSync(migrationsDir)
        .filter((f) => f.endsWith('.sql'))
        .sort(); // Lexicographic — 001_, 002_, etc.

      for (const file of files) {
        try {
          const sql = readFileSync(join(migrationsDir, file), 'utf8');
          await this._pool.query(sql);
        } catch (err) {
          // A failing migration means the schema is half-built — log and refuse to start.
          this._logger.error(`[storage] Migration failed: ${file}`, { file, error: err });
          throw err;
        }
      }
    }

    try {
      await this._revocation.loadAll();
    } catch (err) {
      // Non-fatal: cold cache is acceptable. isRevoked() falls through to DB.
      this._logger.warn('[storage] Revocation cache warm-up failed (cold cache)', { error: err });
    }
    this._revocation.startCoherency();
  }

  /**
   * Close the connection pool. After this, sub-store operations will throw.
   * Idempotent — safe to call multiple times (second call is a no-op).
   */
  async close(): Promise<void> {
    if (this._closed) return;
    this._closed = true;
    // Stop the revocation poll loop before closing the pool.
    this._revocation.stopCoherency();
    // If constructed via fromPool() with ownsPool=false, skip pool.end()
    if (!this._ownsPool) return;
    await this._pool.end();
  }

  // ─── Internal ───────────────────────────────────────────────────────────────

  /**
   * Find the migrations/ directory relative to this file.
   * Tries __dirname (CJS), then indirect eval for import.meta.url (ESM),
   * then process.cwd(). Returns null if not found (published npm consumers
   * don't ship migrations/).
   */
  private _findMigrationsDir(): string | null {
    let moduleDir: string | null = null;
    // CJS path: __dirname is defined natively. Try this first so the CJS
    // dist never runs the ESM-only code below (which the CJS tsconfig
    // would reject at compile time without the @ts-ignore directive).
    try {
      if (typeof __dirname !== 'undefined') {
        moduleDir = __dirname;
      }
    } catch {
      // __dirname undefined in pure ESM — fall through
    }
    if (!moduleDir) {
      try {
        // Indirect eval defers import.meta parse to runtime so CJS doesn't reject it at compile time.
        const metaUrl: string | undefined =
          (0, eval)('typeof import.meta !== "undefined" && import.meta.url') || undefined;
        if (metaUrl) {
          moduleDir = dirname(fileURLToPath(metaUrl));
        }
      } catch {
        // fall through to process.cwd() candidate
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
