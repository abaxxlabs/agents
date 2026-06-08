import { describe, it, expect } from 'vitest';
import { SqliteRuntimeUnavailableError as FromMain, AgentScopeError } from '#index.js';
import { SqliteRuntimeUnavailableError as FromSqlite } from '#storage/sqlite/index.js';

describe('SqliteRuntimeUnavailableError — public export reachability', () => {
  it('is exported from the main entry as a constructable AgentScopeError subclass', () => {
    const err = new FromMain();
    expect(err).toBeInstanceOf(AgentScopeError);
    expect(err.name).toBe('SqliteRuntimeUnavailableError');
    expect(err.code).toBe('SQLITE_RUNTIME_UNAVAILABLE');
  });

  it('is exported from the ./sqlite subpath alongside SqliteStorageBackend', () => {
    expect(typeof FromSqlite).toBe('function');
  });

  it('resolves to the same class on both subpaths so instanceof works regardless of import path', () => {
    expect(FromSqlite).toBe(FromMain);
    expect(new FromSqlite()).toBeInstanceOf(FromMain);
  });
});
