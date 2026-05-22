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
 * SqliteStorageBackend — SQLite implementation of StorageBackend.
 *
 * For local development and single-process deployments. Supports both runtimes:
 *   - Bun: uses the built-in `bun:sqlite` (no install needed).
 *   - Node.js: falls back to `better-sqlite3` (optional peer dep).
 *
 * Importable only via the `@abaxxlabs/agents/sqlite` subpath export — the main
 * entry never loads this file, keeping the native dep optional.
 */

import type {
  StorageBackend,
  SqliteStorageOptions,
  AgentStore,
  AuditStore,
  ContextStore,
  RevocationStore,
  SessionStore,
} from '../types.js';
import { SqliteRuntimeUnavailableError } from '../../errors/index.js';
import { SqliteAgentStore } from './agent-store.js';
import { SqliteAuditStore } from './audit-store.js';
import { SqliteContextStore } from './context-store.js';
import { SqliteRevocationStore } from './revocation-store.js';
import { SqliteSessionStore } from './session-store.js';
import { SQLITE_SCHEMA_STATEMENTS, SQLITE_MIGRATIONS } from './migrations.js';

/**
 * Minimal shared surface for bun:sqlite and better-sqlite3.
 * Avoids unconditionally importing @types/better-sqlite3 (optional dep).
 */
interface SqliteStatement {
  run(...params: unknown[]): { changes: number; lastInsertRowid: number | bigint };
  get(...params: unknown[]): unknown;
  all(...params: unknown[]): unknown[];
}

type SqliteTransactionFn<TArgs extends unknown[], TResult> = (...args: TArgs) => TResult;

interface SqliteTransaction<TArgs extends unknown[], TResult> {
  (...args: TArgs): TResult;
  default(...args: TArgs): TResult;
  deferred(...args: TArgs): TResult;
  immediate(...args: TArgs): TResult;
  exclusive(...args: TArgs): TResult;
}

interface SqliteDatabase {
  prepare(sql: string): SqliteStatement;
  exec(sql: string): unknown;
  close(): void;
  transaction<TArgs extends unknown[], TResult>(
    fn: SqliteTransactionFn<TArgs, TResult>,
  ): SqliteTransaction<TArgs, TResult>;
}

/**
 * Resolve the Database constructor for the current runtime.
 * Tries bun:sqlite first (Bun built-in); falls back to better-sqlite3 (Node.js).
 *
 * @throws {SqliteRuntimeUnavailableError} if neither runtime provides a SQLite implementation.
 */
async function loadSqliteDatabaseCtor(): Promise<new (path: string) => SqliteDatabase> {
  try {
    // @ts-expect-error — bun:sqlite only resolves under Bun; absent from Node's type graph.
    const mod = await import('bun:sqlite');
    return mod.Database;
  } catch {
    // Not running in Bun. Fall through to better-sqlite3.
  }

  try {
    const mod = await import('better-sqlite3');
    return mod.default;
  } catch {
    throw new SqliteRuntimeUnavailableError();
  }
}

/** Options for SqliteStorageBackend. */
export interface SqliteStorageBackendOptions {
  /** HKDF-derived key for session envelope MAC verification. */
  sessionMacKey: Buffer;
}

export class SqliteStorageBackend implements StorageBackend {
  private readonly db: SqliteDatabase;
  private readonly _agents: SqliteAgentStore;
  private readonly _audit: SqliteAuditStore;
  private readonly _context: SqliteContextStore;
  private readonly _revocation: SqliteRevocationStore;
  private readonly _sessions: SqliteSessionStore;

  private constructor(db: SqliteDatabase, sessionMacKey: Buffer) {
    this.db = db;
    /* eslint-disable @typescript-eslint/no-explicit-any -- structural-to-nominal cast: SqliteDatabase doesn't unify with better-sqlite3's nominal Database type */
    this._agents = new SqliteAgentStore(this.db as any);
    this._audit = new SqliteAuditStore(this.db as any);
    this._context = new SqliteContextStore(this.db as any);
    this._revocation = new SqliteRevocationStore(this.db as any);
    this._sessions = new SqliteSessionStore(this.db as any, sessionMacKey);
    /* eslint-enable @typescript-eslint/no-explicit-any */
  }

  /**
   * Create a new SqliteStorageBackend. Use ':memory:' for in-memory databases.
   *
   * @param options - Storage options including the database path.
   * @param backendOpts - Backend options including the session MAC key.
   * @throws {TypeError} if sessionMacKey is missing.
   * @throws {Error} if no SQLite runtime is available.
   */
  static async create(
    options: SqliteStorageOptions,
    backendOpts?: SqliteStorageBackendOptions,
  ): Promise<SqliteStorageBackend> {
    if (!backendOpts?.sessionMacKey) {
      throw new TypeError(
        'SqliteStorageBackend requires a sessionMacKey. ' +
          'Derive one via deriveSessionMacKey(masterKey) from @abaxxlabs/agents.',
      );
    }

    const DatabaseCtor = await loadSqliteDatabaseCtor();
    const db = new DatabaseCtor(options.path) as SqliteDatabase;
    return new SqliteStorageBackend(db, backendOpts.sessionMacKey);
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

  // ─── Lifecycle ──────────────────────────────────────────────────────────────

  /**
   * Create tables, indexes, and triggers. Idempotent (IF NOT EXISTS).
   * Warms the revocation cache so subsequent isRevoked() calls hit memory.
   */
  async initialize(): Promise<void> {
    for (const sql of SQLITE_SCHEMA_STATEMENTS) {
      this.db.exec(sql);
    }
    // SQLite throws "duplicate column" on re-run — catch and ignore (idempotent).
    for (const sql of SQLITE_MIGRATIONS) {
      try {
        this.db.exec(sql);
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        if (!message.includes('duplicate column')) throw err;
      }
    }

    try {
      await this._revocation.loadAll();
    } catch {
      // Non-fatal — table may not exist on first initialize before schema runs.
    }
  }

  /**
   * Close the SQLite database. After this, sub-store operations will throw.
   */
  async close(): Promise<void> {
    this.db.close();
  }
}
