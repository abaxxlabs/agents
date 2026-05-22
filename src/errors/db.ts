import { AgentScopeError } from './base.js';

export class SqliteRuntimeUnavailableError extends AgentScopeError {
  constructor() {
    super(
      'SQLITE_RUNTIME_UNAVAILABLE',
      'SqliteStorageBackend requires a SQLite runtime. ' +
        'Under Bun, bun:sqlite is built in (no install needed). ' +
        'Under Node.js, install the peer dependency: npm install better-sqlite3',
    );
    this.name = 'SqliteRuntimeUnavailableError';
  }
}

export class DbConnectionFailedError extends AgentScopeError {
  constructor(host: string, reason?: string) {
    super(
      'DB_CONNECTION_FAILED',
      `Cannot connect to PostgreSQL at ${host}${reason ? ` — ${reason}` : ''}`,
      { host },
    );
    this.name = 'DbConnectionFailedError';
  }
}
