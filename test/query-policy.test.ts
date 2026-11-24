import { describe, it, expect, beforeAll } from 'vitest';
import { parseSync as parsePgQuery } from 'libpg-query';
import {
  ensurePgQuery,
  assertReadOnlyQuery,
  assertSqlReadsOnlyDeclaredTable,
  type PgParsed,
} from '#sql/query-policy.js';
import type { Did, TableName } from '#types/domain.js';

const testDid = 'did:key:z6MkTest' as Did;
const testTable = 'orders' as TableName;
const parseSync = (sql: string): PgParsed => parsePgQuery(sql) as PgParsed;

beforeAll(async () => {
  await ensurePgQuery();
});

describe('query-policy', () => {
  describe('assertReadOnlyQuery', () => {
    it('accepts a plain SELECT', () => {
      expect(
        assertReadOnlyQuery(parseSync('SELECT ticker, price FROM orders'), testDid),
      ).toBeUndefined();
    });

    it('rejects INSERT', () => {
      expect(() =>
        assertReadOnlyQuery(parseSync("INSERT INTO orders (ticker) VALUES ('BTC')"), testDid),
      ).toThrow('InsertStmt');
    });
  });

  describe('assertSqlReadsOnlyDeclaredTable', () => {
    it('throws when SQL reads from a different table', () => {
      const parsed = parseSync('SELECT ticker FROM employees');
      expect(() => assertSqlReadsOnlyDeclaredTable(parsed, testTable, testDid)).toThrow();
    });
  });
});
