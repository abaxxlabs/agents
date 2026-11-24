import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { Readable } from 'node:stream';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { canonicalMigrationsDir } from '../scripts/migration-config.mjs';
import { ORDERS_PLAINTEXT_DDL, ORDERS_PLAINTEXT_SEED, ORDERS_PLAINTEXT_TEMP_DDL, ORDERS_PLAINTEXT_TEMP_SEED } from '../src/demo-data.mjs';
import { validateDirectSql } from '../src/direct-sql-policy.mjs';
import { DIRECT_SQL_ROW_LIMIT, readCursorRows } from '../src/direct-sql-results.mjs';
import { createSimulator } from '../src/routes-sim.mjs';
import {
  PLAYGROUND_OWNER,
  applyMigration,
  assertOwnershipClaimSafe,
} from '../scripts/setup-policy.mjs';
import {
  MAX_BODY_BYTES,
  ORDER_COLUMNS,
  RequestBodyTooLargeError,
  areKnownOrderColumns,
  consumeBody,
  isConfiguredMockUser,
  isExpectedLoopbackHost,
  isExpectedLoopbackOrigin,
  isJsonContentType,
  isLocalConnection,
  isLoopbackAddress,
  isValidAgentName,
  parseBody,
} from '../src/request-policy.mjs';

const testDir = dirname(fileURLToPath(import.meta.url));
const playgroundRoot = resolve(testDir, '..');
const repoRoot = resolve(playgroundRoot, '..', '..');

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

test('manifest links the repository package', () => {
  const manifest = readJson(join(playgroundRoot, 'package.json'));
  assert.equal(manifest.dependencies['@abaxxlabs/agents'], 'file:../..');
  assert.equal(manifest.scripts.prestart, 'npm run check:linked-agents && npm run build:css');
  assert.equal(manifest.scripts.presetup, 'npm run check:linked-agents');
});

test('setup selects canonical migrations without inferring historical state', () => {
  assert.equal(canonicalMigrationsDir(playgroundRoot), join(repoRoot, 'migrations'));
  const source = readFileSync(join(playgroundRoot, 'scripts', 'setup-db.mjs'), 'utf8');
  assert.match(source, /canonicalMigrationsDir\(root\)/);
  assert.match(source, /prepareMigrationTracking\(pool\)/);
  assert.match(source, /applyMigration\(pool, file, sql\)/);
  assert.ok(source.indexOf('assertSetupPrivileges(pool)') < source.indexOf('claimPlaygroundDatabase(pool)'));
  assert.ok(source.indexOf('claimPlaygroundDatabase(pool)') < source.indexOf('prepareMigrationTracking(pool)'));
  assert.doesNotMatch(source, /historicalMigrationFiles|hasPreTrackingSchema/);
});

test('database readiness probes execute a query against the requested database', () => {
  const compose = readFileSync(join(playgroundRoot, 'docker-compose.yml'), 'utf8');
  assert.match(compose, /psql -U \$\$\{POSTGRES_USER\} -d \$\$\{POSTGRES_DB\} -Atc 'SELECT 1'/);
  assert.doesNotMatch(compose, /pg_isready/);

  const smoke = readFileSync(join(playgroundRoot, 'scripts', 'compose-smoke.mjs'), 'utf8');
  const probe = smoke.slice(
    smoke.indexOf('async function waitForExternalDatabase()'),
    smoke.indexOf('function cleanUp()'),
  );
  assert.match(probe, /'psql'[\s\S]*'-d', 'playground'[\s\S]*'-Atc', 'SELECT 1'/);
  assert.doesNotMatch(probe, /pg_isready/);
});

test('migration SQL and tracking insert share a locked transaction', async () => {
  const calls = [];
  const client = {
    async query(sql, values) {
      calls.push([sql, values]);
      if (sql.startsWith('SELECT 1 FROM demo_migrations')) return { rowCount: 0 };
      return { rowCount: 0, rows: [] };
    },
    release() {
      calls.push(['RELEASE']);
    },
  };
  const applied = await applyMigration({ connect: async () => client }, '001_init.sql', 'CREATE TABLE agents_test()');
  assert.equal(applied, true);
  assert.deepEqual(calls.map(([sql]) => sql), [
    'BEGIN',
    'SELECT pg_advisory_xact_lock(hashtext($1)::bigint)',
    'SELECT 1 FROM demo_migrations WHERE name = $1',
    'CREATE TABLE agents_test()',
    'INSERT INTO demo_migrations (name) VALUES ($1)',
    'COMMIT',
    'RELEASE',
  ]);
});

test('failed migration rolls back without recording it', async () => {
  const calls = [];
  const client = {
    async query(sql) {
      calls.push(sql);
      if (sql.startsWith('SELECT 1 FROM demo_migrations')) return { rowCount: 0 };
      if (sql === 'BROKEN SQL') throw new Error('migration failed');
      return { rowCount: 0, rows: [] };
    },
    release() {
      calls.push('RELEASE');
    },
  };
  await assert.rejects(
    applyMigration({ connect: async () => client }, '001_init.sql', 'BROKEN SQL'),
    /migration failed/,
  );
  assert.ok(calls.includes('ROLLBACK'));
  assert.ok(!calls.some((sql) => sql.startsWith?.('INSERT INTO demo_migrations')));
});

test('playground ownership refuses unmarked business tables and accepts its marker', () => {
  assert.throws(
    () => assertOwnershipClaimSafe({ markerValue: null, businessTables: ['orders'] }),
    /Foreign tables will not be modified/,
  );
  assert.doesNotThrow(
    () => assertOwnershipClaimSafe({ markerValue: PLAYGROUND_OWNER, businessTables: ['orders'] }),
  );
  const source = readFileSync(join(playgroundRoot, 'scripts', 'setup-db.mjs'), 'utf8');
  assert.match(source, /claimPlaygroundDatabase\(pool\)[\s\S]*CREATE TABLE IF NOT EXISTS orders/);
});

test('plaintext fixture is write-protected and reset is a contract no-op', () => {
  assert.match(ORDERS_PLAINTEXT_DDL, /CREATE TABLE IF NOT EXISTS orders_plaintext/);
  assert.equal((ORDERS_PLAINTEXT_SEED.match(/\('/g) ?? []).length, 8);
  assert.match(ORDERS_PLAINTEXT_TEMP_DDL, /CREATE TEMP TABLE orders_plaintext/);
  assert.match(ORDERS_PLAINTEXT_TEMP_DDL, /ON COMMIT DROP/);
  assert.equal((ORDERS_PLAINTEXT_TEMP_SEED.match(/\(\d+, '/g) ?? []).length, 8);
  for (const id of [1, 2, 3, 4, 5, 6, 7, 8]) {
    assert.match(ORDERS_PLAINTEXT_TEMP_SEED, new RegExp(`\\(${id}, '`));
  }
  assert.match(ORDERS_PLAINTEXT_DDL, /created_at\s+TIMESTAMPTZ NOT NULL DEFAULT '2026-01-01T00:00:00Z'/);
  assert.match(ORDERS_PLAINTEXT_TEMP_DDL, /created_at\s+TIMESTAMPTZ NOT NULL DEFAULT '2026-01-01T00:00:00Z'/);
  assert.equal((ORDERS_PLAINTEXT_SEED.match(/2026-01-01T00:00:00Z/g) ?? []).length, 8);
  assert.equal((ORDERS_PLAINTEXT_TEMP_SEED.match(/2026-01-01T00:00:00Z/g) ?? []).length, 8);
  const seedValues = (seed) => [...seed.matchAll(
    /\((?:\d+,\s*)?'([A-Z0-9-]+)',\s*'(BUY|SELL)',\s*([0-9.]+),\s*([0-9.]+),\s*'([^']+)',\s*'([A-Z]+)'(?:,\s*'[^']*')?\)/g,
  )].map((match) => match.slice(1).join('|'));
  assert.deepEqual(seedValues(ORDERS_PLAINTEXT_TEMP_SEED), seedValues(ORDERS_PLAINTEXT_SEED),
    'the per-request copy must carry the same fixture values as the public seed');
  const setup = readFileSync(join(playgroundRoot, 'scripts', 'setup-db.mjs'), 'utf8');
  const simulator = readFileSync(join(playgroundRoot, 'src', 'routes-sim.mjs'), 'utf8');
  assert.match(setup, /ORDERS_PLAINTEXT_DDL/);
  assert.match(setup, /ORDERS_PLAINTEXT_SEED/);
  assert.match(setup, /ALTER TABLE orders_plaintext ALTER COLUMN created_at SET DEFAULT '2026-01-01T00:00:00Z'/);
  assert.match(setup, /ALTER TABLE orders_plaintext OWNER TO CURRENT_USER/);
  assert.doesNotMatch(setup, /OWNER TO \$\{PLAYGROUND_NAIVE_ROLE\}/);
  assert.match(setup, /GRANT SELECT ON TABLE orders_plaintext TO \$\{PLAYGROUND_NAIVE_ROLE\}/);
  assert.doesNotMatch(setup, /GRANT SELECT, UPDATE, DELETE ON TABLE orders_plaintext/);
  assert.doesNotMatch(setup, /GRANT UPDATE|GRANT DELETE/);
  assert.match(setup, /REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC/);
  assert.match(setup, /GRANT TEMPORARY ON DATABASE %I TO %I', current_database\(\), '\$\{PLAYGROUND_NAIVE_ROLE\}'\)/);
  assert.match(setup, /ALTER TABLE orders_plaintext ALTER COLUMN created_at SET NOT NULL/);
  assert.match(setup, /DROP FUNCTION IF EXISTS public\.reset_orders_plaintext_sandbox\(\)/);
  assert.doesNotMatch(setup, /CREATE OR REPLACE FUNCTION public\.reset_orders_plaintext_sandbox/);
  assert.doesNotMatch(setup, /SECURITY DEFINER/);
  assert.doesNotMatch(setup, /reset_orders_plaintext_sandbox\(\) TO \$\{PLAYGROUND_APP_ROLE\}/);
  assert.match(simulator, /ORDERS_PLAINTEXT_TEMP_DDL/);
  assert.match(simulator, /ORDERS_PLAINTEXT_TEMP_SEED/);
  assert.doesNotMatch(simulator, /reset_orders_plaintext_sandbox/);
  assert.doesNotMatch(simulator, /naivePool\.query\('TRUNCATE orders_plaintext'\)|naivePool\.query\(ORDERS_PLAINTEXT_SEED\)/);
});

test('direct SQL policy accepts only bounded orders_plaintext statements', async () => {
  assert.equal((await validateDirectSql('SELECT id FROM orders_plaintext')).statement, 'SelectStmt');
  assert.equal((await validateDirectSql('UPDATE orders_plaintext SET id = id')).statement, 'UpdateStmt');
  assert.equal((await validateDirectSql('DELETE FROM orders_plaintext WHERE id = 1')).statement, 'DeleteStmt');
  assert.equal(
    (await validateDirectSql('SELECT * FROM public.orders_plaintext', { allowedSchemas: ['public'] })).ok,
    true,
    'the sandbox/proof callers may opt into an explicit schema',
  );
  assert.equal(
    (await validateDirectSql('SELECT * FROM sandbox.orders_plaintext', { allowedSchemas: ['sandbox'] })).ok,
    true,
    'the sandbox executor opts into its own schema',
  );
  for (const sql of [
    'SELECT id, instrument FROM orders_plaintext',
    'SELECT * FROM orders_plaintext',
    'SELECT COUNT(*)::int AS count FROM orders_plaintext',
    'UPDATE orders_plaintext SET status = \'CHECKED\' WHERE id = 1',
    'UPDATE orders_plaintext SET price = 0.01',
    'DELETE FROM orders_plaintext WHERE id = 1',
    'DELETE FROM orders_plaintext',
  ]) {
    assert.equal((await validateDirectSql(sql)).ok, true, sql);
  }
});

test('direct SQL policy rejects unsafe or out-of-scope statements', async () => {
  const cases = [
    ['SELECT 1; SELECT 2', /exactly one statement is allowed/],
    ['SELECT * FROM orders', /relation "orders" is not allowed/],
    ['SELECT * FROM agents', /relation "agents" is not allowed/],
    ['SELECT * FROM pg_catalog.pg_user', /relation "pg_catalog.pg_user" is not allowed/],
    ['SELECT * FROM public.orders_plaintext ORDER BY id LIMIT 4', /relation "public.orders_plaintext" is not allowed/],
    ['SELECT * FROM pg_temp.orders_plaintext', /relation "pg_temp.orders_plaintext" is not allowed/],
    ['UPDATE public.orders_plaintext SET status = \'X\' WHERE id = 1', /relation "public.orders_plaintext" is not allowed/],
    ['SELECT COUNT(*) FROM agent_audit', /relation "agent_audit" is not allowed/],
    ['CREATE TABLE evil_orders (id int)', /only SELECT, UPDATE or DELETE/],
    ['DROP TABLE orders_plaintext', /only SELECT, UPDATE or DELETE/],
    ['ALTER TABLE orders_plaintext ADD COLUMN x TEXT', /only SELECT, UPDATE or DELETE/],
    ['TRUNCATE orders_plaintext', /only SELECT, UPDATE or DELETE/],
    ['BEGIN', /only SELECT, UPDATE or DELETE/],
    ['COMMIT', /only SELECT, UPDATE or DELETE/],
    ['SET statement_timeout TO 0', /only SELECT, UPDATE or DELETE/],
    ['WITH x AS (DELETE FROM orders_plaintext RETURNING *) SELECT * FROM x', /CTEs \(WITH clauses\) are not allowed/],
    ['DELETE FROM orders_plaintext RETURNING id', /RETURNING is not allowed/],
    ['SELECT * INTO copied_orders FROM orders_plaintext', /SELECT INTO is not allowed/],
    ['SELECT * FROM orders_plaintext FOR UPDATE', /locking clauses/],
    ['SELECT instrument FROM orders_plaintext WHERE id = (SELECT min(id) FROM orders_plaintext)', /subqueries are not allowed/],
    ['SELECT instrument FROM orders_plaintext WHERE id IN (SELECT id FROM orders_plaintext)', /subqueries are not allowed/],
    ['SELECT instrument FROM orders_plaintext WHERE EXISTS (SELECT 1 FROM orders_plaintext)', /subqueries are not allowed/],
    ['SELECT * FROM (SELECT * FROM orders_plaintext) t', /FROM table expression "RangeSubselect"/],
    ['SELECT * FROM generate_series(1, 3)', /FROM table expression "RangeFunction"/],
    ['SELECT pg_sleep(5) FROM orders_plaintext LIMIT 1', /function "pg_sleep" is not allowed/],
    ["SELECT set_config('statement_timeout', '1ms', true) FROM orders_plaintext LIMIT 1", /function "set_config" is not allowed/],
    ['SELECT pg_advisory_lock(42) FROM orders_plaintext LIMIT 1', /function "pg_advisory_lock" is not allowed/],
    ['SELECT pg_advisory_xact_lock(1) FROM orders_plaintext LIMIT 1', /function "pg_advisory_xact_lock" is not allowed/],
    ['SELECT current_user', /must query orders_plaintext/],
    ['not sql at all', /could not be parsed/],
  ];
  for (const [sql, pattern] of cases) {
    const verdict = await validateDirectSql(sql);
    assert.equal(verdict.ok, false, sql);
    assert.match(verdict.reason, pattern, sql);
  }
});

function simulatorOptions(issueCredential) {
  return {
    pool: { async query() { return { rows: [] }; } },
    directSqlPool: { async connect() { throw new Error('direct SQL is not exercised by this test'); } },
    scope: {
      authenticate: async () => ({ humanDid: 'did:key:demo-operator', issueCredential }),
      listAgents: async () => [],
      createAgentIdentity: async () => ({ did: 'did:key:sim-agent', name: 'sim-agent' }),
    },
    readBody: () => ({}),
    rejected: () => {},
  };
}

function simulatorCredential() {
  return `header.${Buffer.from(JSON.stringify({ exp: Math.floor(Date.now() / 1000) + 3600 })).toString('base64url')}.signature`;
}

test('direct SQL writes to a per-request temporary copy and always rolls back', async (t) => {
  const calls = [];
  const client = {
    async query(sql) {
      calls.push(sql);
      if (sql.startsWith('UPDATE')) return { command: 'UPDATE', rowCount: 3, rows: [] };
      return { command: 'SELECT', rowCount: 0, rows: [] };
    },
    release(...args) {
      calls.push(['RELEASE', ...args]);
    },
  };
  const options = simulatorOptions(async () => simulatorCredential());
  options.directSqlPool = { async connect() { return client; } };
  const statement = "UPDATE orders_plaintext SET status = 'CHECKED' WHERE id <= 3";
  options.readBody = async () => ({ sql: statement });
  const simulator = await createSimulator(options);

  const response = await simulator.routes['POST /api/sim/raw']({});

  assert.deepEqual(response, [200, { ok: true, command: 'UPDATE', rowCount: 3 }]);
  assert.equal(calls[0], 'BEGIN');
  const tempIndex = calls.findIndex((call) => /CREATE TEMP TABLE orders_plaintext/.test(call));
  const seedIndex = calls.findIndex((call) => /INSERT INTO orders_plaintext \(id, instrument/.test(call));
  const statementIndex = calls.indexOf(statement);
  const searchPathIndex = calls.findIndex((call) => /SET LOCAL search_path = pg_temp/.test(call));
  assert.ok(searchPathIndex > 0 && searchPathIndex < tempIndex,
    'the transaction must pin resolution to pg_temp before creating the copy');
  assert.ok(tempIndex > 0, 'the temporary copy must be created inside the transaction');
  assert.match(calls[tempIndex], /ON COMMIT DROP/);
  assert.ok(seedIndex > tempIndex, 'the copy must be seeded before the statement runs');
  assert.ok(statementIndex > seedIndex, 'the visitor statement runs against the seeded copy');
  assert.ok(calls.indexOf('ROLLBACK') > statementIndex, 'the transaction must always roll back');
  assert.ok(!calls.includes('COMMIT'), 'the direct SQL path must never commit');
  const sessionSettings = calls.filter((call) => typeof call === 'string' && /^\s*SET\b/i.test(call));
  assert.ok(sessionSettings.length >= 2, 'the transaction must set statement_timeout and search_path');
  assert.ok(sessionSettings.every((call) => /^\s*SET LOCAL\b/i.test(call)),
    'every session setting must be transaction-local so a pooled connection is released clean');
  assert.deepEqual(calls.at(-1), ['RELEASE']);
});

test('reset keeps the contract response without touching the database', async () => {
  const simulator = await createSimulator(simulatorOptions(async () => simulatorCredential()));

  assert.deepEqual(await simulator.routes['POST /api/sim/reset']({}), [200, { ok: true, rows: 8 }]);
});

function cursorClient(totalRows, rowFactory = (i) => ({ id: i })) {
  const calls = [];
  let offset = 0;
  return {
    calls,
    query: async (sql) => {
      calls.push(sql);
      if (sql.startsWith('DECLARE direct_sql_cursor')) return { rowCount: 0 };
      if (sql.startsWith('FETCH FORWARD 1 FROM direct_sql_cursor')) {
        if (offset < totalRows) {
          offset += 1;
          return { rowCount: 1, rows: [rowFactory(offset)] };
        }
        return { rowCount: 0, rows: [] };
      }
      if (sql.startsWith('CLOSE direct_sql_cursor')) return { rowCount: 0 };
      throw new Error(`unexpected query: ${sql}`);
    },
  };
}

test('SELECT results stream through DECLARE/FETCH without executing the user SQL directly', async () => {
  const sql = 'SELECT id FROM orders_plaintext';
  const client = cursorClient(3);
  const { rows, limitedBy } = await readCursorRows(client, sql);
  assert.equal(rows.length, 3);
  assert.equal(limitedBy, undefined);
  assert.equal(client.calls[0], `DECLARE direct_sql_cursor NO SCROLL CURSOR FOR ${sql}`);
  assert.ok(!client.calls.includes(sql), 'the user SQL must never be sent directly');
  assert.ok(client.calls.every((call) => !call.startsWith('SELECT')));
  assert.equal(client.calls.filter((call) => call.startsWith('FETCH')).length, 4, '3 row fetches + 1 empty probe');
  assert.match(client.calls.at(-1), /^CLOSE direct_sql_cursor$/);
});

test('cursor reads stop at the 100-row limit after one probe fetch', async () => {
  const client = cursorClient(105);
  const { rows, limitedBy } = await readCursorRows(client, 'SELECT id FROM orders_plaintext');
  assert.equal(rows.length, DIRECT_SQL_ROW_LIMIT);
  assert.equal(limitedBy, 'rows');
  assert.equal(client.calls.filter((call) => call.startsWith('FETCH')).length, 101);
  assert.equal(client.calls.filter((call) => call.startsWith('FETCH')).length, rows.length + 1);
});

test('request policy restricts users, names, columns, and unsafe endpoint callers', () => {
  assert.equal(isConfiguredMockUser('alice'), true);
  assert.equal(isConfiguredMockUser('bob'), true);
  assert.equal(isConfiguredMockUser('mallory'), false);
  assert.equal(isValidAgentName('agent_01-worker'), true);
  assert.equal(isValidAgentName('a'.repeat(64)), true);
  assert.equal(isValidAgentName('a'.repeat(65)), false);
  assert.equal(isValidAgentName('<img>'), false);
  assert.equal(areKnownOrderColumns(ORDER_COLUMNS), true);
  assert.equal(areKnownOrderColumns(['orders.id']), false);
  assert.equal(areKnownOrderColumns(['other.instrument']), false);
  assert.equal(isLoopbackAddress('127.0.0.1'), true);
  assert.equal(isLoopbackAddress('localhost'), true);
  assert.equal(isLoopbackAddress('::1'), true);
  assert.equal(isLoopbackAddress('::ffff:127.0.0.1'), true);
  assert.equal(isLoopbackAddress('10.0.0.4'), false);
  assert.equal(isExpectedLoopbackHost('localhost:3100'), true);
  assert.equal(isExpectedLoopbackHost('127.0.0.1:3100'), true);
  assert.equal(isExpectedLoopbackHost('[::1]:3100'), true);
  assert.equal(isExpectedLoopbackHost('attacker.example:3100'), false);
  assert.equal(isExpectedLoopbackHost('127.0.0.1.attacker.example:3100'), false);
  assert.equal(isExpectedLoopbackHost('localhost.attacker.example:3100'), false);
  assert.equal(isExpectedLoopbackOrigin('http://localhost:3100'), true);
  assert.equal(isExpectedLoopbackOrigin('http://127.0.0.1:3100'), true);
  assert.equal(isExpectedLoopbackOrigin('null'), false);
  assert.equal(isExpectedLoopbackOrigin('https://attacker.example'), false);
  assert.equal(isExpectedLoopbackOrigin('http://127.0.0.1.attacker.example:3100'), false);
  assert.equal(isExpectedLoopbackOrigin('http://localhost.attacker.example:3100'), false);
  assert.equal(isJsonContentType('application/json'), true);
  assert.equal(isJsonContentType('application/json; charset=utf-8'), true);
  assert.equal(isJsonContentType('text/plain'), false);
  assert.equal(isLocalConnection('127.0.0.1', null), true);
  assert.equal(isLocalConnection('172.21.0.1', ['172.21.0.1']), true);
  assert.equal(isLocalConnection('::ffff:172.21.0.1', ['172.21.0.1']), true);
  assert.equal(isLocalConnection('172.21.0.3', ['172.21.0.1']), false);
  assert.equal(isLocalConnection('172.21.0.3', null), false);
});

test('body limit accepts exactly 64 KiB and rejects more, before JSON parsing', async () => {
  const exact = Readable.from([Buffer.alloc(MAX_BODY_BYTES, 'x')]);
  await consumeBody(exact);
  assert.equal(exact.bodyRaw.length, MAX_BODY_BYTES);

  const singleChunk = Readable.from([Buffer.alloc(MAX_BODY_BYTES + 1, 'x')]);
  await assert.rejects(consumeBody(singleChunk), RequestBodyTooLargeError);

  const splitChunks = Readable.from([Buffer.alloc(MAX_BODY_BYTES, 'x'), Buffer.alloc(1, 'y')]);
  await assert.rejects(consumeBody(splitChunks), RequestBodyTooLargeError);

  const empty = Readable.from([]);
  await consumeBody(empty);
  assert.deepEqual(parseBody(empty), {});

  const json = Readable.from([Buffer.from(JSON.stringify({ humanDid: 'alice' }))]);
  await consumeBody(json);
  assert.deepEqual(parseBody(json), { humanDid: 'alice' });

  const invalid = Readable.from([Buffer.from('not-json')]);
  await consumeBody(invalid);
  assert.throws(() => parseBody(invalid), SyntaxError);
});
