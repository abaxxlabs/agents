import { describe, it, expect, beforeAll, beforeEach, vi } from 'vitest';
import { parseSync } from 'libpg-query';
import { authorizeQuery, ensurePgQuery } from '#sql/query-policy.js';
import type { Did, TableName } from '#types/domain.js';

vi.mock('libpg-query', async (importActual) => {
  const actual = await importActual<typeof import('libpg-query')>();
  return { ...actual, parseSync: vi.fn(actual.parseSync) };
});

const agentDid = 'did:key:zParseContract' as Did;
const tableName = 'patients' as TableName;

const scope = (...columns: string[]): Map<string, Set<string>> =>
  new Map(columns.map((column) => [column, new Set(['read'])]));

const inScope = scope('patients.name', 'patients.dob');

const authorize = (sql: string, columnActionMap = inScope) =>
  authorizeQuery({ sql, tableName, agentDid, columnActionMap });

describe('SQL policy parser-invocation contract', () => {
  beforeAll(async () => {
    await ensurePgQuery();
  });

  beforeEach(() => {
    vi.mocked(parseSync).mockClear();
  });

  it('parses an authorized query exactly once', async () => {
    await expect(authorize('SELECT name, dob FROM patients')).resolves.toBeUndefined();
    expect(parseSync).toHaveBeenCalledTimes(1);
  });
});
