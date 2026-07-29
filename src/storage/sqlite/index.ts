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
 * SQLite backend for local or single-process use. It loads bun:sqlite or the
 * optional better-sqlite3 dependency only through the SQLite subpath export.
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
import { SqliteRuntimeUnavailableError } from '#errors/index.js';
import { SqliteAgentStore } from './agent-store.js';
import { SqliteAuditStore } from './audit-store.js';
import { SqliteContextStore } from './context-store.js';
import { SqliteRevocationStore } from './revocation-store.js';
import { SqliteSessionStore } from './session-store.js';
import { SQLITE_SCHEMA_STATEMENTS, SQLITE_MIGRATIONS } from './migrations.js';
import type { Logger } from '#observability/logger.js';
import { getLogger } from '#observability/logger.js';

export { SqliteRuntimeUnavailableError } from '#errors/index.js';

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
 * Loads the current runtime's SQLite constructor.
 * @throws {SqliteRuntimeUnavailableError} When neither implementation is available.
 */
async function loadSqliteDatabaseCtor(
  logger: Logger,
): Promise<new (path: string) => SqliteDatabase> {
  if (process.versions.bun) {
    try {
      // @ts-expect-error bun:sqlite is intentionally absent from Node's type graph.
      const mod = await import('bun:sqlite');
      return mod.Database;
    } catch (err) {
      logger.error('[storage] Failed to load bun:sqlite; falling back to better-sqlite3', {
        error: err,
      });
    }
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
  /** Optional diagnostic logger. */
  logger?: Logger;
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
   * Creates a SQLite backend without initializing its schema.
   * @param options Storage options including the database path.
   * @param backendOpts Backend options including the session MAC key.
   * @throws {TypeError} When sessionMacKey is missing.
   * @throws {SqliteRuntimeUnavailableError} When no SQLite runtime is available.
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

    const DatabaseCtor = await loadSqliteDatabaseCtor(getLogger(backendOpts.logger));
    const db = new DatabaseCtor(options.path) as SqliteDatabase;
    return new SqliteStorageBackend(db, backendOpts.sessionMacKey);
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

  /** Creates the schema, applies additive migrations, and warms revocations. */
  async initialize(): Promise<void> {
    for (const sql of SQLITE_SCHEMA_STATEMENTS) {
      this.db.exec(sql);
    }
    for (const sql of SQLITE_MIGRATIONS) {
      try {
        this.db.exec(sql);
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        if (!message.includes('duplicate column')) throw err;
      }
    }

    await this._revocation.loadAll();
  }

  /** Closes the SQLite database. */
  async close(): Promise<void> {
    this.db.close();
  }
}
