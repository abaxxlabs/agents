import { SqliteRuntimeUnavailableError as FromMain } from '#index.js';
import { SqliteRuntimeUnavailableError as FromSqlite } from '#storage/sqlite/index.js';

describe('SqliteRuntimeUnavailableError — public export reachability', () => {
  it('resolves to the same class on both subpaths so instanceof works regardless of import path', () => {
    expect(FromSqlite).toBe(FromMain);
    expect(new FromSqlite()).toBeInstanceOf(FromMain);
  });
});
