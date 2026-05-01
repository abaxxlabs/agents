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

import { describe, it, expect, beforeAll } from 'vitest';
import { parseSync } from 'libpg-query';
import {
  ensurePgQuery,
  assertReadOnlyQuery,
  findMutationInAst,
  extractColumnRefs,
  extractTargetColumns,
  extractPhysicalTableRefs,
  assertSqlReadsOnlyDeclaredTable,
  type PgAstNode,
} from '../src/sql/query-policy.js';
import type { Did, TableName } from '../src/domain-types.js';

const testDid = 'did:key:z6MkTest' as Did;
const testTable = 'orders' as TableName;

beforeAll(async () => {
  await ensurePgQuery();
});

describe('query-policy', () => {
  describe('assertReadOnlyQuery', () => {
    it('accepts a plain SELECT', async () => {
      await expect(
        assertReadOnlyQuery('SELECT ticker, price FROM orders', testDid),
      ).resolves.toBeUndefined();
    });

    it('rejects INSERT', async () => {
      await expect(
        assertReadOnlyQuery("INSERT INTO orders (ticker) VALUES ('BTC')", testDid),
      ).rejects.toThrow('InsertStmt');
    });

    it('rejects UPDATE', async () => {
      await expect(
        assertReadOnlyQuery("UPDATE orders SET ticker = 'ETH'", testDid),
      ).rejects.toThrow('UpdateStmt');
    });

    it('rejects DELETE', async () => {
      await expect(
        assertReadOnlyQuery('DELETE FROM orders', testDid),
      ).rejects.toThrow('DeleteStmt');
    });

    it('rejects DROP TABLE', async () => {
      await expect(
        assertReadOnlyQuery('DROP TABLE orders', testDid),
      ).rejects.toThrow('DropStmt');
    });
  });

  describe('findMutationInAst', () => {
    it('returns null for a SELECT statement', () => {
      const parsed = parseSync('SELECT 1');
      expect(findMutationInAst(parsed.stmts[0].stmt as PgAstNode)).toBeNull();
    });

    it('returns InsertStmt for an INSERT', () => {
      const parsed = parseSync("INSERT INTO t (a) VALUES ('x')");
      expect(findMutationInAst(parsed.stmts[0].stmt as PgAstNode)).toBe('InsertStmt');
    });

    it('returns null for null/undefined input', () => {
      expect(findMutationInAst(null)).toBeNull();
      expect(findMutationInAst(undefined)).toBeNull();
    });
  });

  describe('extractColumnRefs', () => {
    it('extracts column names from a SELECT target list', () => {
      const parsed = parseSync('SELECT ticker, price FROM orders');
      const select = (parsed.stmts[0].stmt as PgAstNode).SelectStmt as PgAstNode;
      const targetList = select.targetList as Array<{ ResTarget?: { val?: PgAstNode } }>;
      const cols = targetList.flatMap((t) => extractColumnRefs(t.ResTarget?.val as PgAstNode));
      expect(cols).toContain('ticker');
      expect(cols).toContain('price');
    });

    it('returns * for SELECT *', () => {
      const parsed = parseSync('SELECT * FROM orders');
      const select = (parsed.stmts[0].stmt as PgAstNode).SelectStmt as PgAstNode;
      const targetList = select.targetList as Array<{ ResTarget?: { val?: PgAstNode } }>;
      const cols = targetList.flatMap((t) => extractColumnRefs(t.ResTarget?.val as PgAstNode));
      expect(cols).toContain('*');
    });
  });

  describe('extractTargetColumns', () => {
    it('extracts columns from SELECT list', () => {
      const parsed = parseSync('SELECT ticker, side, qty FROM orders');
      const cols = extractTargetColumns(parsed);
      expect(cols).toEqual(expect.arrayContaining(['ticker', 'side', 'qty']));
    });
  });

  describe('extractPhysicalTableRefs', () => {
    it('extracts a simple table name', () => {
      const parsed = parseSync('SELECT 1 FROM orders');
      const refs = extractPhysicalTableRefs(parsed.stmts[0].stmt as PgAstNode);
      expect(refs).toContain('orders');
    });

    it('extracts schema-qualified table name', () => {
      const parsed = parseSync('SELECT 1 FROM public.orders');
      const refs = extractPhysicalTableRefs(parsed.stmts[0].stmt as PgAstNode);
      expect(refs).toContain('public.orders');
    });

    it('excludes CTE names from physical refs', () => {
      const parsed = parseSync(
        'WITH cte AS (SELECT 1 FROM orders) SELECT * FROM cte',
      );
      const refs = extractPhysicalTableRefs(parsed.stmts[0].stmt as PgAstNode);
      expect(refs).toContain('orders');
      expect(refs).not.toContain('cte');
    });
  });

  describe('assertSqlReadsOnlyDeclaredTable', () => {
    it('passes when SQL matches declared table', () => {
      const parsed = parseSync('SELECT ticker FROM orders');
      expect(() =>
        assertSqlReadsOnlyDeclaredTable(parsed, testTable, testDid),
      ).not.toThrow();
    });

    it('throws when SQL reads from a different table', () => {
      const parsed = parseSync('SELECT ticker FROM employees');
      expect(() =>
        assertSqlReadsOnlyDeclaredTable(parsed, testTable, testDid),
      ).toThrow();
    });
  });

  describe('libpg-query AST shape regression (ABXAGNTS-384)', () => {
    function stripLocations(obj: unknown): unknown {
      if (Array.isArray(obj)) return obj.map(stripLocations);
      if (obj && typeof obj === 'object') {
        const out: Record<string, unknown> = {};
        for (const [k, v] of Object.entries(obj)) {
          if (k === 'location') continue;
          out[k] = stripLocations(v);
        }
        return out;
      }
      return obj;
    }

    it('SELECT AST matches pinned libpg-query@17.7.3 shape', () => {
      const parsed = parseSync('SELECT id, name FROM patients');
      const stmt = stripLocations(parsed.stmts[0].stmt);

      expect(stmt).toEqual({
        SelectStmt: {
          targetList: [
            { ResTarget: { val: { ColumnRef: { fields: [{ String: { sval: 'id' } }] } } } },
            { ResTarget: { val: { ColumnRef: { fields: [{ String: { sval: 'name' } }] } } } },
          ],
          fromClause: [
            { RangeVar: { relname: 'patients', inh: true, relpersistence: 'p' } },
          ],
          limitOption: 'LIMIT_OPTION_DEFAULT',
          op: 'SETOP_NONE',
        },
      });
    });

    it('INSERT AST top-level key is InsertStmt', () => {
      const parsed = parseSync("INSERT INTO t (a) VALUES ('x')");
      const stmtKeys = Object.keys(parsed.stmts[0].stmt);
      expect(stmtKeys).toEqual(['InsertStmt']);
    });

    it('writable CTE nesting matches expected shape', () => {
      const parsed = parseSync(
        "WITH del AS (DELETE FROM audit RETURNING *) SELECT * FROM del",
      );
      const stmt = parsed.stmts[0].stmt as PgAstNode;
      const select = stmt.SelectStmt as PgAstNode;
      const withClause = select.withClause as { ctes?: Array<{ CommonTableExpr?: { ctequery?: PgAstNode } }> };

      expect(withClause).toBeDefined();
      expect(withClause.ctes).toHaveLength(1);
      const cteQuery = withClause.ctes![0].CommonTableExpr?.ctequery;
      expect(cteQuery).toBeDefined();
      expect(Object.keys(cteQuery!)).toEqual(['DeleteStmt']);
    });
  });
});
