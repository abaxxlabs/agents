import assert from 'node:assert/strict';
import { existsSync, readFileSync, realpathSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { Readable } from 'node:stream';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import { canonicalMigrationsDir } from '../scripts/migration-config.mjs';
import { ORDERS_PLAINTEXT_DDL, ORDERS_PLAINTEXT_SEED } from '../src/demo-data.mjs';
import { validateDirectSql } from '../src/direct-sql-policy.mjs';
import {
  createDeadlineExecutor,
  DIRECT_SQL_REQUEST_TIMEOUT_MS,
  DIRECT_SQL_RESPONSE_BYTE_LIMIT,
  DIRECT_SQL_ROW_LIMIT,
  readCursorRows,
  selectPayloadBytes,
} from '../src/direct-sql-results.mjs';
import {
  adminDatabaseUrlEnvironmentEntry,
  loadEnvironment,
  resolveAdminDatabaseUrl,
} from '../src/env-file.mjs';
import { cleanUpFailedDirectSql, createSimulator, directSqlErrorPayload } from '../src/routes-sim.mjs';
import {
  DEFAULT_DATABASE_URL,
  PLAYGROUND_NAIVE_PASSWORD_ENV,
  PLAYGROUND_OWNER,
  appendMissingEnvEntries,
  applyMigration,
  assertMigrationBootstrapSafe,
  assertOwnershipClaimSafe,
  assertSetupPrivileges,
  classifyEncryptionState,
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
  resolveHostGatewayIps,
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

const linkedPackage = join(playgroundRoot, 'node_modules', '@abaxxlabs', 'agents');
test('installed package link resolves to the repository root with the same version', () => {
  assert.ok(existsSync(linkedPackage), 'npm install must create the repository package link');
  assert.equal(realpathSync(linkedPackage), realpathSync(repoRoot));
  assert.equal(
    readJson(join(linkedPackage, 'package.json')).version,
    readJson(join(repoRoot, 'package.json')).version,
  );
});

test('package lock records a local link without private or local tarballs', () => {
  const manifest = readJson(join(playgroundRoot, 'package.json'));
  const lock = readJson(join(playgroundRoot, 'package-lock.json'));
  assert.equal(lock.packages[''].dependencies['@abaxxlabs/agents'], 'file:../..');
  assert.equal(lock.packages['node_modules/@abaxxlabs/agents'].resolved, '../..');
  assert.equal(lock.packages['node_modules/@abaxxlabs/agents'].link, true);

  for (const value of Object.values(manifest.dependencies)) {
    assert.doesNotMatch(value, /\.tgz(?:$|[?#])/i);
  }
  for (const entry of Object.values(lock.packages)) {
    if (!entry.resolved || !/\.tgz(?:$|[?#])/i.test(entry.resolved)) continue;
    assert.equal(new URL(entry.resolved).origin, 'https://registry.npmjs.org');
  }
});

test('status pill renders the library version', () => {
  const source = readFileSync(join(playgroundRoot, 'public', 'app.js'), 'utf8');
  assert.match(source, /server-status/);
  assert.match(source, /body\.libraryVersion/);
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

test('setup privilege probe verifies the required DDL without leaving changes', async () => {
  const calls = [];
  const client = {
    async query(sql, values) {
      calls.push(sql);
      return { rowCount: 0, rows: [] };
    },
    release() {
      calls.push('RELEASE');
    },
  };
  await assertSetupPrivileges({ connect: async () => client });
  assert.deepEqual(calls, [
    'BEGIN',
    'CREATE TABLE agents_demo_playground_setup_probe (probe INT)',
    'CREATE ROLE agents_demo_playground_setup_probe_role',
    "ALTER ROLE agents_demo_playground_setup_probe_role WITH LOGIN PASSWORD 'agents-demo-setup-probe'",
    'ALTER TABLE agents_demo_playground_setup_probe OWNER TO agents_demo_playground_setup_probe_role',
    'ROLLBACK',
    'RELEASE',
  ]);
});

test('failed setup privilege probe rolls back and reports no changes', async () => {
  const calls = [];
  const client = {
    async query(sql) {
      calls.push(sql);
      if (sql.startsWith('ALTER ROLE')) throw new Error('permission denied');
      return { rowCount: 0, rows: [] };
    },
    release() {
      calls.push('RELEASE');
    },
  };
  await assert.rejects(
    assertSetupPrivileges({ connect: async () => client }),
    /lacks a required database privilege and no changes were made/,
  );
  assert.ok(calls.includes('ROLLBACK'));
  assert.ok(!calls.includes('COMMIT'));
});

test('migration bootstrap rejects an untracked canonical agents schema', () => {
  assert.throws(
    () => assertMigrationBootstrapSafe({ hasTracking: false, hasCanonicalAgents: true }),
    /fresh dedicated database/,
  );
  assert.doesNotThrow(
    () => assertMigrationBootstrapSafe({ hasTracking: true, hasCanonicalAgents: true }),
  );
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

test('encryption recovery only skips a complete encrypted state', () => {
  assert.equal(classifyEncryptionState({
    dataType: 'bytea', hasKey: true, hasMetadata: true, metadataEncrypted: true, keyMatches: true,
  }), 'encrypted');
  assert.equal(classifyEncryptionState({
    dataType: 'numeric', hasKey: false, hasMetadata: false, metadataEncrypted: null, keyMatches: false,
  }), 'plaintext');
  for (const state of [
    { dataType: 'bytea', hasKey: true, hasMetadata: false, metadataEncrypted: null, keyMatches: false },
    { dataType: 'bytea', hasKey: true, hasMetadata: true, metadataEncrypted: true, keyMatches: false },
    { dataType: 'numeric', hasKey: false, hasMetadata: true, metadataEncrypted: false, keyMatches: false },
    { dataType: 'numeric', hasKey: true, hasMetadata: true, metadataEncrypted: true, keyMatches: true },
  ]) {
    assert.equal(classifyEncryptionState(state), 'inconsistent');
  }
});

test('env setup persists runtime credentials without overwriting existing content', () => {
  assert.match(DEFAULT_DATABASE_URL, /localhost:54322/);
  assert.equal(
    appendMissingEnvEntries('CUSTOM=value\nDATABASE_URL=postgresql:\/\/custom\n', {
      AGENTS_MASTER_KEY: 'generated-key',
      [PLAYGROUND_NAIVE_PASSWORD_ENV]: 'generated-password',
      PLAYGROUND_RUNTIME_DATABASE_URL: 'postgresql://agents_playground_app:runtime-password@localhost/playground',
    }),
    'CUSTOM=value\nDATABASE_URL=postgresql://custom\nAGENTS_MASTER_KEY=generated-key\nPLAYGROUND_NAIVE_DB_PASSWORD=generated-password\nPLAYGROUND_RUNTIME_DATABASE_URL=postgresql://agents_playground_app:runtime-password@localhost/playground\n',
  );
  const source = readFileSync(join(playgroundRoot, 'scripts', 'setup-db.mjs'), 'utf8');
  assert.match(source, /appendFileSync\(envPath, nextEnv\.slice\(existingEnv\.length\)\)/);
  assert.match(source, /PLAYGROUND_NAIVE_PASSWORD_ENV/);
  assert.match(source, /PLAYGROUND_RUNTIME_DATABASE_URL_ENV/);
});

test('setup persists the resolved admin URL only when existing config cannot provide it to startup', () => {
  const explicitUrl = 'postgresql://postgres:secret@db.example.test:5432/playground';
  const runtimeUrl = 'postgresql://agents_playground_app:runtime-password@db.example.test:5432/playground';
  const defaultEnv = appendMissingEnvEntries('', {
    AGENTS_MASTER_KEY: 'generated-key',
    [PLAYGROUND_NAIVE_PASSWORD_ENV]: 'generated-password',
    PLAYGROUND_RUNTIME_DATABASE_URL: runtimeUrl,
    ...adminDatabaseUrlEnvironmentEntry('', DEFAULT_DATABASE_URL),
  });
  const startupEnv = {};
  loadEnvironment(defaultEnv, startupEnv);
  assert.equal(resolveAdminDatabaseUrl(startupEnv), DEFAULT_DATABASE_URL);
  assert.equal((defaultEnv.match(/postgresql:\/\//g) ?? []).length, 2,
    'the config stores only the administrative and runtime URLs');

  const explicitConfig = `DATABASE_URL=${explicitUrl}\n`;
  assert.deepEqual(adminDatabaseUrlEnvironmentEntry(explicitConfig, explicitUrl), {},
    'a persisted explicit DATABASE_URL already supplies startup, so no duplicate URL is written');
  const explicitStartupEnv = {};
  loadEnvironment(explicitConfig, explicitStartupEnv);
  assert.equal(resolveAdminDatabaseUrl(explicitStartupEnv), explicitUrl);

  const setupSource = readFileSync(join(playgroundRoot, 'scripts', 'setup-db.mjs'), 'utf8');
  const serverSource = readFileSync(join(playgroundRoot, 'src', 'server.mjs'), 'utf8');
  assert.match(setupSource, /adminDatabaseUrlEnvironmentEntry\(existingEnv, adminDatabaseUrl\)/);
  assert.match(serverSource, /resolveAdminDatabaseUrl\(process\.env\)/);
});

test('env parser keeps explicit environment values', () => {
  const env = { DATABASE_URL: 'postgresql://explicit' };
  loadEnvironment('DATABASE_URL=postgresql://from-file\nAGENTS_MASTER_KEY=key\n', env);
  assert.deepEqual(env, {
    DATABASE_URL: 'postgresql://explicit',
    AGENTS_MASTER_KEY: 'key',
  });
  const server = readFileSync(join(playgroundRoot, 'src', 'server.mjs'), 'utf8');
  const setup = readFileSync(join(playgroundRoot, 'scripts', 'setup-db.mjs'), 'utf8');
  assert.match(server, /loadEnvFile\(envPath\)/);
  assert.match(setup, /loadEnvFile\(envPath\)/);
});

test('plaintext schema stays in setup and simulator reset uses a privileged fixed function', () => {
  assert.match(ORDERS_PLAINTEXT_DDL, /CREATE TABLE IF NOT EXISTS orders_plaintext/);
  assert.equal((ORDERS_PLAINTEXT_SEED.match(/\('/g) ?? []).length, 8);
  const setup = readFileSync(join(playgroundRoot, 'scripts', 'setup-db.mjs'), 'utf8');
  const simulator = readFileSync(join(playgroundRoot, 'src', 'routes-sim.mjs'), 'utf8');
  assert.match(setup, /ORDERS_PLAINTEXT_DDL/);
  assert.match(setup, /ORDERS_PLAINTEXT_SEED/);
  assert.match(setup, /ALTER TABLE orders_plaintext OWNER TO CURRENT_USER/);
  assert.doesNotMatch(setup, /OWNER TO \$\{PLAYGROUND_NAIVE_ROLE\}/);
  assert.match(setup, /GRANT SELECT, UPDATE, DELETE ON TABLE orders_plaintext TO \$\{PLAYGROUND_NAIVE_ROLE\}/);
  assert.doesNotMatch(setup, /GRANT ALL PRIVILEGES ON TABLE orders_plaintext TO \$\{PLAYGROUND_NAIVE_ROLE\}/);
  assert.doesNotMatch(setup, /GRANT ALL PRIVILEGES ON SEQUENCE orders_plaintext_id_seq TO \$\{PLAYGROUND_NAIVE_ROLE\}/);
  assert.match(setup, /SECURITY DEFINER/);
  assert.match(setup, /REVOKE ALL ON FUNCTION public\.reset_orders_plaintext_sandbox\(\) FROM PUBLIC/);
  assert.match(setup, /GRANT EXECUTE ON FUNCTION public\.reset_orders_plaintext_sandbox\(\) TO \$\{PLAYGROUND_APP_ROLE\}/);
  assert.match(simulator, /pool\.query\('SELECT public\.reset_orders_plaintext_sandbox\(\)'\)/);
  assert.doesNotMatch(simulator, /naivePool\.query\('TRUNCATE orders_plaintext'\)|naivePool\.query\(ORDERS_PLAINTEXT_SEED\)/);
});

test('direct SQL policy accepts only bounded orders_plaintext statements', async () => {
  assert.equal((await validateDirectSql('SELECT id FROM orders_plaintext')).statement, 'SelectStmt');
  assert.equal((await validateDirectSql('UPDATE orders_plaintext SET id = id')).statement, 'UpdateStmt');
  assert.equal((await validateDirectSql('DELETE FROM orders_plaintext WHERE id = 1')).statement, 'DeleteStmt');
  for (const sql of [
    'SELECT id, instrument FROM orders_plaintext',
    'SELECT * FROM orders_plaintext',
    'SELECT COUNT(*)::int AS count FROM orders_plaintext',
    'SELECT * FROM public.orders_plaintext ORDER BY id LIMIT 4',
    'SELECT instrument FROM orders_plaintext WHERE id = (SELECT min(id) FROM orders_plaintext)',
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

test('direct SQL timeout payloads distinguish statement and lock timeouts', () => {
  assert.deepEqual(directSqlErrorPayload({ code: '57014', message: 'canceling statement due to statement timeout' }), {
    ok: false,
    error: 'TimeoutError',
    kind: 'statement',
    message: 'Statement cancelled by PostgreSQL after 2s (statement_timeout)',
  });
  assert.deepEqual(directSqlErrorPayload({ code: '55P03', message: 'canceling statement due to lock timeout' }), {
    ok: false,
    error: 'TimeoutError',
    kind: 'lock',
    message: 'Statement cancelled by PostgreSQL after waiting 1s for a lock (lock_timeout)',
  });
  const other = directSqlErrorPayload(Object.assign(new Error('permission denied for table orders'), { code: '42501' }));
  assert.equal(other.ok, false);
  assert.equal(other.error, 'PostgresError');
  assert.equal(other.kind, undefined);
  assert.equal(other.message, 'Database permission denied');
  assert.equal(directSqlErrorPayload(null).error, 'PostgresError');
});

function simulatorOptions(issueCredential) {
  return {
    databaseUrl: 'postgresql://agents_playground_app:app-password@localhost/playground',
    naiveDbPassword: 'naive-password',
    pool: {},
    scope: {
      authenticate: async () => ({ humanDid: 'did:key:demo-operator', issueCredential }),
      listAgents: async () => [],
      createAgentIdentity: async () => ({ did: 'did:key:sim-agent', name: 'sim-agent' }),
    },
    readBody: () => ({}),
    rejected: () => {},
    hostGatewayIps: null,
  };
}

test('simulator keeps its naive pool open after initialization until close()', async (t) => {
  const pools = [];
  t.mock.method(pg, 'Pool', function FakePool(options) {
    const pool = { options, endCount: 0, on() { return this; }, async end() { this.endCount++; } };
    pools.push(pool);
    return pool;
  });
  const credential = `header.${Buffer.from(JSON.stringify({ exp: Math.floor(Date.now() / 1000) + 3600 })).toString('base64url')}.signature`;
  const simulator = await createSimulator(simulatorOptions(async () => credential));

  assert.equal(pools.length, 1);
  assert.equal(new URL(pools[0].options.connectionString).username, 'agents_playground_naive');
  assert.equal(pools[0].endCount, 0);
  await simulator.close();
  assert.equal(pools[0].endCount, 1);
});

test('simulator closes its naive pool and rethrows an initialization error', async (t) => {
  let endCount = 0;
  t.mock.method(pg, 'Pool', function FakePool() {
    return { on() { return this; }, async end() { endCount++; } };
  });
  const originalError = new Error('credential issuance failed');

  await assert.rejects(
    createSimulator(simulatorOptions(async () => { throw originalError; })),
    (err) => err === originalError,
  );
  assert.equal(endCount, 1);
});

test('simulator preserves the initialization error if closing the naive pool fails', async (t) => {
  const closeError = new Error('pool shutdown failed');
  const originalError = new Error('credential issuance failed');
  const logged = [];
  let endCount = 0;
  t.mock.method(pg, 'Pool', function FakePool() {
    return { on() { return this; }, async end() { endCount++; throw closeError; } };
  });
  t.mock.method(console, 'error', (...args) => logged.push(args));

  await assert.rejects(
    createSimulator(simulatorOptions(async () => { throw originalError; })),
    (err) => err === originalError,
  );
  assert.equal(endCount, 1);
  assert.deepEqual(logged[0][1], { type: 'Error' });
  assert.doesNotMatch(JSON.stringify(logged), /pool shutdown failed/);
});

test('failed direct SQL rolls back and normally releases a clean client', async () => {
  const calls = [];
  const releases = [];
  const originalError = Object.assign(new Error('permission denied for table orders'), { code: '42501' });
  const client = {
    query: async (sql) => {
      calls.push(sql);
      return { rowCount: 0, rows: [] };
    },
    release: (...args) => releases.push(args),
  };

  const payload = await cleanUpFailedDirectSql(client, originalError);
  assert.deepEqual(calls, ['ROLLBACK']);
  assert.deepEqual(releases, [[]]);
  assert.deepEqual(payload, directSqlErrorPayload(originalError));
});

test('failed rollback discards the client while returning the original SQL error', async () => {
  const releases = [];
  const logs = [];
  const originalError = Object.assign(new Error('permission denied for table orders'), { code: '42501' });
  const rollbackError = new Error('connection lost during rollback');
  const client = {
    query: async () => { throw rollbackError; },
    release: (...args) => releases.push(args),
  };

  const payload = await cleanUpFailedDirectSql(client, originalError, {
    error: (...args) => logs.push(args),
  });
  assert.deepEqual(releases, [[true]]);
  assert.deepEqual(payload, directSqlErrorPayload(originalError));
  assert.equal(logs.length, 1);
  assert.match(logs[0][0], /ROLLBACK failed; discarding pooled connection/);
  assert.deepEqual(logs[0][1], { type: 'Error' });
  assert.doesNotMatch(JSON.stringify(logs), /connection lost during rollback/);
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

test('cursor reads stop when the serialized response would exceed 64 KiB', async () => {
  const row = () => ({ id: 1, counterparty: 'x'.repeat(6_000) });
  const client = cursorClient(150, row);
  const { rows, limitedBy } = await readCursorRows(client, 'SELECT id, counterparty FROM orders_plaintext');
  assert.equal(limitedBy, 'responseBytes');
  assert.ok(rows.length >= 1 && rows.length < DIRECT_SQL_ROW_LIMIT);
  assert.ok(selectPayloadBytes(rows, limitedBy) <= DIRECT_SQL_RESPONSE_BYTE_LIMIT);
  assert.ok(selectPayloadBytes([...rows, row()], 'responseBytes') > DIRECT_SQL_RESPONSE_BYTE_LIMIT, 'must stop exactly at the byte boundary');
});

test('a single oversized row is withheld rather than returned partially', async () => {
  const client = cursorClient(1, () => ({ blob: 'x'.repeat(200_000) }));
  const { rows, limitedBy } = await readCursorRows(client, 'SELECT blob FROM orders_plaintext');
  assert.equal(rows.length, 0);
  assert.equal(limitedBy, 'responseBytes');
  assert.equal(client.calls.filter((call) => call.startsWith('FETCH')).length, 1);
  assert.match(client.calls.at(-1), /^CLOSE direct_sql_cursor$/);
});

test('the cursor is closed even when a fetch fails', async () => {
  const client = cursorClient(10);
  let fetches = 0;
  const original = client.query.bind(client);
  client.query = async (sql) => {
    if (sql.startsWith('FETCH')) {
      fetches += 1;
      if (fetches === 3) {
        throw Object.assign(new Error('canceling statement due to statement timeout'), { code: '57014' });
      }
    }
    return original(sql);
  };
  await assert.rejects(() => readCursorRows(client, 'SELECT id FROM orders_plaintext'), /statement timeout/);
  assert.match(client.calls.at(-1), /^CLOSE direct_sql_cursor$/);
});

test('cursor fetches share one decreasing request deadline', async () => {
  let now = 0;
  let statementTimeout = 0;
  let fetches = 0;
  const timeouts = [];
  const client = {
    calls: [],
    query: async (sql) => {
      client.calls.push(sql);
      const match = sql.match(/^SET LOCAL statement_timeout = '(\d+)ms'$/);
      if (match) {
        statementTimeout = Number(match[1]);
        timeouts.push(statementTimeout);
        return { rowCount: 0, rows: [] };
      }
      if (sql.startsWith('DECLARE')) return { rowCount: 0, rows: [] };
      if (sql.startsWith('FETCH')) {
        fetches += 1;
        now += 700;
        if (700 > statementTimeout) {
          throw Object.assign(new Error('canceling statement due to statement timeout'), { code: '57014' });
        }
        return { rowCount: 1, rows: [{ id: fetches }] };
      }
      if (sql.startsWith('CLOSE')) return { rowCount: 0, rows: [] };
      throw new Error(`unexpected query: ${sql}`);
    },
  };
  const execute = createDeadlineExecutor(client, DIRECT_SQL_REQUEST_TIMEOUT_MS, () => now);

  await assert.rejects(
    () => readCursorRows(client, 'SELECT id FROM orders_plaintext', execute),
    (err) => err.code === '57014',
  );
  assert.deepEqual(timeouts, [2000, 2000, 1300, 600]);
  assert.equal(fetches, 3, 'each 700ms FETCH is below 2s, but the third exceeds its remaining 600ms');
  assert.equal(client.calls.filter((sql) => sql.startsWith('FETCH')).length, 3);
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

test('host gateway resolution includes the DNS fallback address', async () => {
  const gateways = await resolveHostGatewayIps(async (hostname) => {
    assert.equal(hostname, 'host.docker.internal');
    return { address: '172.17.0.1', family: 4 };
  });

  assert.ok(gateways?.includes('172.17.0.1'));
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

test('frontend avoids unsafe identity rendering and distinguishes infrastructure failures', () => {
  const app = readFileSync(join(playgroundRoot, 'public', 'app.js'), 'utf8');
  assert.doesNotMatch(app, /li\.innerHTML|div\.innerHTML/);
  assert.match(app, /function clearUserState\(\)/);
  assert.match(app, /state\.userAlias && state\.userAlias !== radio\.value/);
  assert.match(app, /identity changed; authenticate before creating an agent or issuing a credential/);
  assert.match(app, /const AUDIT_VISIBLE_LIMIT = 5/);
  const auditView = readFileSync(join(playgroundRoot, 'public', 'audit-view.js'), 'utf8');
  assert.match(auditView, /Show \$\{hiddenCount\} more audit/);
  const styles = readFileSync(join(playgroundRoot, 'public', 'styles.css'), 'utf8');
  assert.match(auditView, /audit-expand/);
  assert.match(styles, /font-size:\s*0?\.68rem/);
  assert.match(app, /method === 'POST' \? \{ 'content-type': 'application\/json' \} : undefined/);
  assert.match(app, /hash links checked/);
});
