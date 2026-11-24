import { loadModule, parseSync } from 'libpg-query';
import { logSafeError } from './safe-diagnostics.mjs';

const ALLOWED_STATEMENTS = new Set(['SelectStmt', 'UpdateStmt', 'DeleteStmt']);
const ALLOWED_FUNCTIONS = new Set(['count', 'min']);
const ALLOWED_RELATION = 'orders_plaintext';
const ALLOWED_SCHEMAS = new Set();
export const SANDBOX_PLAINTEXT_SCHEMA = 'sandbox';
const FORBIDDEN_TABLE_EXPRESSIONS = new Set([
  'RangeSubselect',
  'RangeTableFunction',
  'RangeView',
  'RangeFunction',
]);

let parserReady = false;

/**
 * Validates that a direct-SQL request stays inside its disposable data plane.
 * The Playground accepts only unqualified orders_plaintext references so the
 * statement cannot escape the per-request temporary copy; the shared sandbox
 * executor opts into an explicit schema through allowedSchemas.
 * @param {string} sql
 * @param {{ allowedSchemas?: ReadonlySet<string> | string[] }} [options]
 * @returns {{ ok: true, statement: string } | { ok: false, reason: string }}
 */
export async function validateDirectSql(sql, options = {}) {
  if (!parserReady) {
    try {
      await loadModule();
      parserReady = true;
    } catch (err) {
      logSafeError(console, 'error', 'SQL parser module failed to load', err);
      return { ok: false, reason: 'SQL parser is unavailable', kind: 'unavailable' };
    }
  }
  let parsed;
  try {
    parsed = parseSync(sql);
  } catch {
    return { ok: false, reason: 'SQL could not be parsed as a valid PostgreSQL statement', kind: 'parse' };
  }
  const statements = parsed?.stmts ?? [];
  if (statements.length !== 1) {
    const reason = statements.length === 0
      ? 'SQL must contain exactly one statement'
      : `exactly one statement is allowed, got ${statements.length}`;
    return { ok: false, reason };
  }
  const root = statements[0]?.stmt;
  const rootType = root && typeof root === 'object' ? Object.keys(root)[0] : undefined;
  if (!rootType || !ALLOWED_STATEMENTS.has(rootType)) {
    return { ok: false, reason: `only SELECT, UPDATE or DELETE statements are allowed (got ${rootType ?? 'empty statement'})` };
  }
  if (rootType === 'UpdateStmt') {
    const targets = root.UpdateStmt?.targetList ?? [];
    if (targets.some((target) => target?.ResTarget?.name === 'sandbox_id')) {
      return { ok: false, reason: 'the sandbox_id column is immutable and cannot be updated' };
    }
  }
  if (containsKey(root, 'withClause')) {
    return { ok: false, reason: 'CTEs (WITH clauses) are not allowed' };
  }
  const allowedSchemas = new Set(options.allowedSchemas ?? ALLOWED_SCHEMAS);
  const state = { tables: 0, allowedSchemas };
  const reason = checkNode(root, state);
  if (reason) return { ok: false, reason };
  if (state.tables === 0) {
    return { ok: false, reason: 'the statement must query orders_plaintext' };
  }
  return { ok: true, statement: rootType };
}

function containsKey(node, target) {
  if (node == null || typeof node !== 'object') return false;
  if (Array.isArray(node)) return node.some((item) => containsKey(item, target));
  return Object.entries(node).some(([key, value]) => key === target || containsKey(value, target));
}

function checkNode(node, state) {
  if (node == null || typeof node !== 'object') return null;
  if (Array.isArray(node)) {
    for (const item of node) {
      const reason = checkNode(item, state);
      if (reason) return reason;
    }
    return null;
  }
  for (const key of Object.keys(node)) {
    const value = node[key];
    if (value == null) continue;
    if (key === 'intoClause') return 'SELECT INTO is not allowed';
    if (key === 'returningList' && Array.isArray(value) && value.length > 0) {
      return 'RETURNING is not allowed';
    }
    if (key === 'lockingClause') return 'locking clauses (FOR UPDATE / FOR SHARE) are not allowed';
    if (key === 'SubLink') {
      return 'subqueries are not allowed; direct SQL must be a single flat statement';
    }
    if (FORBIDDEN_TABLE_EXPRESSIONS.has(key)) {
      return `FROM table expression "${key}" is not allowed; only plain orders_plaintext references are valid`;
    }
    if (key === 'RangeVar' || key === 'relation') {
      const relname = value.relname;
      const schemaname = value.schemaname;
      if (relname === ALLOWED_RELATION && (schemaname === undefined || state.allowedSchemas.has(schemaname))) {
        state.tables += 1;
        continue;
      }
      const label = schemaname ? `${schemaname}.${relname}` : String(relname ?? 'unknown');
      return `relation "${label}" is not allowed; direct SQL may only use orders_plaintext`;
    }
    if (key === 'FuncCall') {
      const parts = Array.isArray(value.funcname) ? value.funcname : [];
      const name = parts.length > 0 ? parts.at(-1)?.String?.sval : undefined;
      if (typeof name !== 'string' || !ALLOWED_FUNCTIONS.has(name)) {
        return `function "${name ?? 'unknown'}" is not allowed; only count() and min() may be called`;
      }
    }
    const reason = checkNode(value, state);
    if (reason) return reason;
  }
  return null;
}
