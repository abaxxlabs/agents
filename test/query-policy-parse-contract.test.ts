import { describe, it, expect, beforeAll, beforeEach, vi } from 'vitest';
import { parseSync } from 'libpg-query';
import { authorizeQuery, ensurePgQuery } from '#sql/query-policy.js';
import { QueryRejectedError } from '#errors/index.js';
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

  it('parses a query rejected for a mutation exactly once', async () => {
    await expect(authorize("INSERT INTO patients (name) VALUES ('x')")).rejects.toThrow(
      QueryRejectedError,
    );
    expect(parseSync).toHaveBeenCalledTimes(1);
  });

  it('parses a query rejected for an out-of-scope column exactly once', async () => {
    await expect(authorize('SELECT name, ssn FROM patients')).rejects.toMatchObject({
      name: 'ScopeViolationError',
      requestedColumns: ['patients.ssn'],
    });
    expect(parseSync).toHaveBeenCalledTimes(1);
  });

  it('parses a query rejected for reading another table exactly once', async () => {
    await expect(authorize('SELECT name FROM employees')).rejects.toThrow(QueryRejectedError);
    expect(parseSync).toHaveBeenCalledTimes(1);
  });

  it('parses a wildcard projection rejected by column scope exactly once', async () => {
    await expect(authorize('SELECT * FROM patients')).rejects.toMatchObject({
      name: 'ScopeViolationError',
      requestedColumns: ['patients.*'],
    });
    expect(parseSync).toHaveBeenCalledTimes(1);
  });

  // A literal `table.*` grant is the only scope shape that reaches the wildcard backstop.
  it('parses a wildcard projection rejected by the wildcard backstop exactly once', async () => {
    await expect(authorize('SELECT * FROM patients', scope('patients.*'))).rejects.toMatchObject({
      name: 'ScopeViolationError',
      requestedColumns: ['*'],
    });
    expect(parseSync).toHaveBeenCalledTimes(1);
  });

  it('parses a malformed query exactly once', async () => {
    await expect(authorize('SELECT FROM WHERE')).rejects.toThrow('SQL parse error');
    expect(parseSync).toHaveBeenCalledTimes(1);
  });
});
