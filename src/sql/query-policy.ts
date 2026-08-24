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
 * SQL query validation policy — pure functions with no ScopeEngine state dependency.
 *
 * @module
 */

import { loadModule, parseSync } from 'libpg-query';
import { QueryRejectedError, ScopeViolationError } from '#errors/index.js';

import type { Did, TableName } from '#types/domain.js';

// ─── SQL Parser (libpg-query WASM) ──────────────────────────────

let pgQueryLoaded = false;

/** Load the libpg-query WASM module (idempotent). */
export async function ensurePgQuery(): Promise<void> {
  if (pgQueryLoaded) return;
  await loadModule();
  pgQueryLoaded = true;
}

/** Statement types that modify data — anything other than SELECT */
const MUTATION_STMT_TYPES = new Set([
  'InsertStmt',
  'UpdateStmt',
  'DeleteStmt',
  'DropStmt',
  'TruncateStmt',
  'AlterTableStmt',
  'CreateStmt',
  'CreateTableAsStmt',
  'GrantStmt',
  'RevokeStmt',
  'CreateRoleStmt',
  'AlterRoleStmt',
  'DropRoleStmt',
  'CreateSchemaStmt',
  'AlterObjectSchemaStmt',
  'CreateFunctionStmt',
  'CreateTrigStmt',
  'CreateExtensionStmt',
  'DropOwnedStmt',
  'ReassignOwnedStmt',
  'CopyStmt',
  'CreatedbStmt',
  'DropdbStmt',
]);

/**
 * libpg-query AST nodes are recursive untyped JSON trees. The library does not
 * publish a typed schema, so we treat each node as an opaque record and walk it
 * structurally. Casts to specific shapes happen at known node-name keys
 * (SelectStmt, ColumnRef, RangeVar, etc.) where the wire format is documented.
 */
export type PgAstNode = Record<string, unknown>;

/**
 * Recursively check an AST node for mutation statements.
 * Returns the name of the first mutation found, or null if pure read-only.
 */
export function findMutationInAst(node: PgAstNode | null | undefined): string | null {
  if (!node || typeof node !== 'object') return null;

  for (const key of Object.keys(node)) {
    if (MUTATION_STMT_TYPES.has(key)) return key;
  }

  // Check CTEs — writable CTEs hide mutations in ctequery
  const selectStmt = node.SelectStmt as PgAstNode | undefined;
  const withClause = selectStmt?.withClause as
    | { ctes?: Array<{ CommonTableExpr?: { ctequery?: PgAstNode } }> }
    | undefined;
  if (withClause?.ctes) {
    for (const cte of withClause.ctes) {
      const cteQuery = cte.CommonTableExpr?.ctequery;
      if (cteQuery) {
        const mutation = findMutationInAst(cteQuery);
        if (mutation) return mutation;
      }
    }
  }

  // Check subqueries in FROM clause
  const fromClause = selectStmt?.fromClause as
    | Array<{ RangeSubselect?: { subquery?: PgAstNode } }>
    | undefined;
  if (fromClause) {
    for (const fromItem of fromClause) {
      const subquery = fromItem.RangeSubselect?.subquery;
      if (subquery) {
        const mutation = findMutationInAst(subquery);
        if (mutation) return mutation;
      }
    }
  }

  return null;
}

/** Caller must have awaited ensurePgQuery(); the parser is not self-initializing here. */
function parseQuery(sql: string, agentDid: Did): PgParsed {
  try {
    return parseSync(sql) as PgParsed;
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Invalid SQL';
    throw new QueryRejectedError(agentDid, `SQL parse error: ${message}`);
  }
}

/**
 * Validate that a parsed statement tree is a pure read-only query.
 * @throws QueryRejectedError if the query contains any mutation statements
 */
export function assertReadOnlyQuery(parsed: PgParsed, agentDid: Did): void {
  for (const stmtWrapper of parsed.stmts) {
    const stmt = stmtWrapper.stmt;
    const mutation = findMutationInAst(stmt);
    if (mutation) {
      throw new QueryRejectedError(
        agentDid,
        `Query contains ${mutation} — only pure SELECT queries are allowed.`,
      );
    }

    // Top-level statement must be a SELECT
    if (!stmt?.SelectStmt) {
      const stmtType = stmt ? (Object.keys(stmt)[0] ?? 'unknown') : 'unknown';
      throw new QueryRejectedError(
        agentDid,
        `Query is a ${stmtType} — only SELECT queries are allowed.`,
      );
    }
  }
}

// ─── Projection Boundary ────────────────────────────────────────

/**
 * Recursively extract all column references from a libpg-query AST node.
 * Returns unqualified column names — qualification with table is done by the caller.
 */
export function extractColumnRefs(node: PgAstNode | null | undefined): string[] {
  if (!node || typeof node !== 'object') return [];

  const columns: string[] = [];

  const columnRef = node.ColumnRef as
    | { fields?: Array<{ A_Star?: unknown; String?: { sval?: string; str?: string } }> }
    | undefined;
  if (columnRef) {
    const fields = columnRef.fields;
    if (fields) {
      // libpg-query represents qualified refs (e.g., patients.name) as multiple
      // String fields: [{String: "patients"}, {String: "name"}]. Only the LAST
      // field is the column name; earlier fields are table/schema qualifiers.
      const hasAStar = fields.some((f) => f.A_Star !== undefined);
      if (hasAStar) {
        columns.push('*');
      } else {
        const lastField = fields[fields.length - 1];
        if (lastField?.String) {
          const colName = lastField.String.sval ?? lastField.String.str;
          if (colName) columns.push(colName);
        }
      }
    }
    return columns;
  }

  for (const key of Object.keys(node)) {
    const val = node[key];
    if (Array.isArray(val)) {
      for (const item of val) {
        columns.push(...extractColumnRefs(item as PgAstNode));
      }
    } else if (typeof val === 'object' && val !== null) {
      columns.push(...extractColumnRefs(val as PgAstNode));
    }
  }

  return columns;
}

export interface PgParsedStmt {
  stmt?: PgAstNode;
}

export interface PgParsed {
  stmts: PgParsedStmt[];
}

/**
 * Extract all column names referenced in the SELECT target list of a parsed SQL statement.
 * Returns '*' if any target uses SELECT *.
 */
export function extractTargetColumns(parsed: PgParsed): string[] {
  const columns: string[] = [];

  for (const stmtWrapper of parsed.stmts) {
    const selectStmt = stmtWrapper.stmt?.SelectStmt as
      | { targetList?: Array<{ ResTarget?: { val?: PgAstNode } }> }
      | undefined;
    if (!selectStmt?.targetList) continue;

    for (const target of selectStmt.targetList) {
      const resTarget = target.ResTarget;
      if (!resTarget?.val) continue;
      columns.push(...extractColumnRefs(resTarget.val));
    }
  }

  return columns;
}

/**
 * Extract ALL column names referenced anywhere in a parsed SQL statement,
 * including WHERE, ORDER BY, HAVING, JOIN ON, and subqueries.
 * Prevents boolean oracle attacks where an attacker references encrypted
 * columns in WHERE clauses to infer values without selecting them.
 */
export function extractAllReferencedColumns(parsed: PgParsed): string[] {
  const columns: string[] = [];
  for (const stmtWrapper of parsed.stmts) {
    const selectStmt = stmtWrapper.stmt?.SelectStmt as PgAstNode | undefined;
    if (!selectStmt) continue;
    columns.push(...extractColumnRefs(selectStmt));
  }
  return columns;
}

/**
 * Extract physical table names from a parsed SELECT tree. CTE names are tracked
 * and skipped, but their query bodies are still inspected so a CTE cannot hide
 * reads from a different base table behind the caller-declared table.
 */
export function extractPhysicalTableRefs(
  node: PgAstNode | null | undefined,
  cteNames: Set<string> = new Set(),
): string[] {
  if (!node || typeof node !== 'object') return [];

  const rangeVar = node.RangeVar as { relname?: string; schemaname?: string } | undefined;
  if (rangeVar) {
    const relname = rangeVar.relname;
    if (!relname || cteNames.has(relname)) return [];
    const schemaname = rangeVar.schemaname;
    return [schemaname ? `${schemaname}.${relname}` : relname];
  }

  const selectStmt = node.SelectStmt as PgAstNode | undefined;
  if (selectStmt) {
    const refs: string[] = [];
    const localCteNames = new Set(cteNames);
    const withClause = selectStmt.withClause as
      | { ctes?: Array<{ CommonTableExpr?: { ctename?: string; ctequery?: PgAstNode } }> }
      | undefined;
    const ctes = withClause?.ctes ?? [];

    for (const cte of ctes) {
      const cteName = cte.CommonTableExpr?.ctename;
      if (cteName) localCteNames.add(cteName);
    }
    for (const cte of ctes) {
      refs.push(...extractPhysicalTableRefs(cte.CommonTableExpr?.ctequery, localCteNames));
    }

    for (const key of Object.keys(selectStmt)) {
      if (key === 'withClause') continue;
      const val = selectStmt[key];
      if (Array.isArray(val)) {
        for (const item of val)
          refs.push(...extractPhysicalTableRefs(item as PgAstNode, localCteNames));
      } else if (typeof val === 'object' && val !== null) {
        refs.push(...extractPhysicalTableRefs(val as PgAstNode, localCteNames));
      }
    }

    return refs;
  }

  const refs: string[] = [];
  for (const key of Object.keys(node)) {
    const val = node[key];
    if (Array.isArray(val)) {
      for (const item of val) refs.push(...extractPhysicalTableRefs(item as PgAstNode, cteNames));
    } else if (typeof val === 'object' && val !== null) {
      refs.push(...extractPhysicalTableRefs(val as PgAstNode, cteNames));
    }
  }
  return refs;
}

/** @throws QueryRejectedError if the SQL reads from a table other than the declared one */
export function assertSqlReadsOnlyDeclaredTable(
  parsed: PgParsed,
  tableName: TableName,
  agentDid: Did,
): void {
  const declaredHasSchema = tableName.includes('.');
  const physicalTables = Array.from(
    new Set(parsed.stmts.flatMap((stmtWrapper) => extractPhysicalTableRefs(stmtWrapper.stmt))),
  );

  if (physicalTables.length === 0) {
    throw new QueryRejectedError(agentDid, 'Query must read from the declared table.');
  }

  const mismatched = physicalTables.filter((table) => {
    if (declaredHasSchema) return table !== tableName;
    return table !== tableName || table.includes('.');
  });
  if (mismatched.length > 0) {
    throw new QueryRejectedError(
      agentDid,
      `Declared table "${tableName}" does not match SQL table "${mismatched[0]}".`,
    );
  }
}

function readableColumns(columnActionMap: Map<string, Set<string>>): string[] {
  return Array.from(columnActionMap)
    .filter(([, actions]) => actions.has('read'))
    .map(([column]) => column);
}

/**
 * Check that every column referenced ANYWHERE in the query — SELECT, WHERE,
 * ORDER BY, HAVING, JOIN ON — is granted read by the presented credentials.
 *
 * @throws ScopeViolationError if any referenced column lacks read access
 */
function assertColumnScope(
  parsed: PgParsed,
  tableName: TableName,
  columnActionMap: Map<string, Set<string>>,
  agentDid: Did,
): void {
  // Parser output is unqualified, so qualify with the declared table before matching scope.
  const referenced = new Set<string>();
  for (const column of extractAllReferencedColumns(parsed)) {
    referenced.add(`${tableName}.${column}`);
  }

  const lackingRead = Array.from(referenced).filter(
    (column) => !columnActionMap.get(column)?.has('read'),
  );
  if (lackingRead.length > 0) {
    throw new ScopeViolationError(agentDid, lackingRead, readableColumns(columnActionMap));
  }
}

/**
 * Backstop for credentials that grant a literal `table.*`. Every other scope
 * shape already fails assertColumnScope, which sees the wildcard as `table.*`.
 * Reads only the top-level target list, so set operations are not covered.
 *
 * @throws ScopeViolationError if a top-level select target is a wildcard
 */
function assertNoWildcardTarget(
  parsed: PgParsed,
  columnActionMap: Map<string, Set<string>>,
  agentDid: Did,
): void {
  if (extractTargetColumns(parsed).includes('*')) {
    throw new ScopeViolationError(agentDid, ['*'], readableColumns(columnActionMap));
  }
}

export interface QueryAuthorization {
  sql: string;
  tableName: TableName;
  agentDid: Did;
  /** Qualified column name to the actions the presented credentials grant on it. */
  columnActionMap: Map<string, Set<string>>;
}

/**
 * Authorize a scoped query. The SQL is parsed once and every policy check runs
 * against that single syntax tree. Mutations are detected from the parse tree
 * rather than by pattern matching, so writable CTEs and subquery mutations
 * cannot slip through.
 *
 * @throws QueryRejectedError on unparseable SQL, mutations, or reads outside the declared table
 * @throws ScopeViolationError when the query references columns without read access
 */
export async function authorizeQuery(input: QueryAuthorization): Promise<void> {
  await ensurePgQuery();

  const parsed = parseQuery(input.sql, input.agentDid);

  assertReadOnlyQuery(parsed, input.agentDid);
  assertColumnScope(parsed, input.tableName, input.columnActionMap, input.agentDid);
  assertSqlReadsOnlyDeclaredTable(parsed, input.tableName, input.agentDid);
  assertNoWildcardTarget(parsed, input.columnActionMap, input.agentDid);
}
