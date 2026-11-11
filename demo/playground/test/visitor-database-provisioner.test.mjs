import assert from 'node:assert/strict';
import test from 'node:test';
import pg from 'pg';
import { PLAYGROUND_OWNER } from '../scripts/setup-policy.mjs';
import { createVisitorDatabaseProvisioner } from '../src/visitor-database-provisioner.mjs';

const adminDatabaseUrl = 'postgresql://postgres:admin-password@localhost:5432/postgres';
const appDatabaseUrl = 'postgresql://agents_playground_app:app-password@localhost:5432/playground_template?application_name=playground';
const templateDatabaseName = 'playground_template';

function mockDatabase(t, {
  failAt,
  failure,
  failDrop,
  failCreate,
  failDiscovery,
  templateName = templateDatabaseName,
  extraDatabases = [],
} = {}) {
  const calls = [];
  const events = [];
  const clients = [];
  const databases = new Map([
    [templateName, { owner: 'postgres', is_template: true, marker: PLAYGROUND_OWNER, connections: 0 }],
    ...extraDatabases,
  ]);
  const adminPool = {
    options: { connectionString: adminDatabaseUrl },
    endCount: 0,
    async end() { this.endCount++; },
    async query(sql, params = []) {
      calls.push([sql, params]);
      events.push(sql);
      if (sql === 'SELECT current_user AS role') return { rows: [{ role: 'postgres' }] };
      if (sql.startsWith('CREATE DATABASE ')) {
        const [, name, template] = sql.match(/^CREATE DATABASE "([a-z0-9_]+)" TEMPLATE "([a-z0-9_]+)"$/) ?? [];
        assert.equal(template, templateName);
        if (failCreate) {
          databases.set(name, { owner: 'other', is_template: false, marker: null, connections: 0 });
          throw failCreate;
        }
        assert.equal(databases.has(name), false);
        databases.set(name, { owner: 'postgres', is_template: false, marker: PLAYGROUND_OWNER, connections: 0 });
        return { rows: [] };
      }
      if (failAt && (sql.startsWith(failAt) || sql.endsWith(failAt))) throw failure;
      if (sql.startsWith('REVOKE CONNECT ') || sql.startsWith('GRANT CONNECT ')) return { rows: [] };
      if (sql.includes('FROM pg_database') && sql.includes('left(datname, length($1))')) {
        if (failDiscovery) throw failDiscovery;
        const [prefix, excludedName] = params;
        return { rows: [...databases.keys()]
          .filter((name) => name.startsWith(prefix) && name !== excludedName)
          .sort()
          .map((datname) => ({ datname })) };
      }
      if (sql.includes('FROM pg_database WHERE datname = $1')) {
        const database = databases.get(params[0]);
        return { rows: database ? [{ owner: database.owner, is_template: database.is_template }] : [] };
      }
      if (sql.includes('FROM pg_stat_activity WHERE datname = $1')) {
        return { rows: [{ count: databases.get(params[0]).connections }] };
      }
      if (sql.startsWith('DROP DATABASE ')) {
        const [, name] = sql.match(/^DROP DATABASE "([a-z0-9_]+)"$/) ?? [];
        const dropError = typeof failDrop === 'function' ? failDrop(name) : failDrop;
        if (dropError) throw dropError;
        assert.equal(databases.has(name), true);
        databases.delete(name);
        return { rows: [] };
      }
      throw new Error(`Unexpected administrative query: ${sql}`);
    },
  };
  t.mock.method(pg, 'Client', function FakeClient({ connectionString }) {
    const url = new URL(connectionString);
    const name = url.pathname.slice(1);
    assert.equal(url.username, 'postgres');
    const client = {
      name,
      endCount: 0,
      async connect() { events.push(`inspection.connect:${name}`); },
      async query(sql, params) {
        assert.equal(sql, 'SELECT value FROM public.demo_playground_metadata WHERE key = $1');
        assert.deepEqual(params, ['owner']);
        events.push(`inspection.query:${name}`);
        const marker = databases.get(name)?.marker;
        return { rows: marker ? [{ value: marker }] : [] };
      },
      async end() { this.endCount++; events.push(`inspection.end:${name}`); },
    };
    clients.push(client);
    return client;
  });
  return { adminPool, calls, events, clients, databases };
}

async function provisioner(adminPool, selectedTemplateName = templateDatabaseName) {
  return createVisitorDatabaseProvisioner({
    adminPool,
    adminDatabaseUrl,
    templateDatabaseName: selectedTemplateName,
    appDatabaseUrl: appDatabaseUrl.replace(templateDatabaseName, selectedTemplateName),
  });
}

function visitorName(suffix) {
  return `agents_playground_visitor_${suffix.repeat(32)}`;
}

test('creates a distinct safe clone with both CONNECT grants and only the app URL', async (t) => {
  const { adminPool, calls, events, clients, databases } = mockDatabase(t);
  const api = await provisioner(adminPool);
  const { databaseName, appDatabaseUrl: visitorUrl } = await api.createVisitorDatabase();

  assert.match(databaseName, /^agents_playground_visitor_[0-9a-f]{32}$/);
  assert.ok(Buffer.byteLength(databaseName) <= 63);
  assert.deepEqual(calls.slice(1).map(([sql]) => sql), [
    `CREATE DATABASE "${databaseName}" TEMPLATE "${templateDatabaseName}"`,
    `REVOKE CONNECT ON DATABASE "${databaseName}" FROM PUBLIC`,
    `GRANT CONNECT ON DATABASE "${databaseName}" TO agents_playground_app`,
    `GRANT CONNECT ON DATABASE "${databaseName}" TO agents_playground_naive`,
  ]);
  const expectedUrl = new URL(appDatabaseUrl);
  expectedUrl.pathname = `/${databaseName}`;
  assert.equal(visitorUrl, expectedUrl.toString());
  assert.equal(new URL(visitorUrl).username, 'agents_playground_app');
  assert.equal(databases.get(databaseName).owner, 'postgres');
  assert.equal(adminPool.endCount, 0);

  await api.dropVisitorDatabase(databaseName);
  assert.equal(clients.length, 1);
  assert.equal(clients[0].endCount, 1);
  assert.ok(events.indexOf(`inspection.end:${databaseName}`) < events.indexOf(`DROP DATABASE "${databaseName}"`));
  assert.equal(databases.has(databaseName), false);
  assert.equal(adminPool.endCount, 0);
  await assert.rejects(api.dropVisitorDatabase(databaseName), /does not exist/);
  assert.equal(calls.filter(([sql]) => sql === `DROP DATABASE "${databaseName}"`).length, 1);
});

test('rejects invalid DROP names and the template before any database query', async (t) => {
  const { adminPool, calls, clients, databases } = mockDatabase(t);
  const api = await provisioner(adminPool);
  for (const name of [templateDatabaseName, 'visitor_a', 'agents_playground_visitor_',
    `agents_playground_visitor_${'a'.repeat(33)}`, `agents_playground_visitor_${'a'.repeat(31)}"; DROP DATABASE postgres;--`]) {
    await assert.rejects(api.dropVisitorDatabase(name), /Invalid Playground visitor database name/);
  }
  assert.equal(calls.length, 1);
  assert.equal(clients.length, 0);
  assert.equal(databases.has(templateDatabaseName), true);
});

test('rejects an inspection URL for a different administrative pool', async (t) => {
  const { adminPool, calls } = mockDatabase(t);
  await assert.rejects(createVisitorDatabaseProvisioner({
    adminPool,
    adminDatabaseUrl: 'postgresql://postgres:admin-password@other-host/postgres',
    templateDatabaseName,
    appDatabaseUrl,
  }), /must use the same connection string/);
  assert.equal(calls.length, 0);
});

test('refuses DROP when owner, template flag, marker, or connections are wrong', async (t) => {
  const { adminPool, calls, clients, databases } = mockDatabase(t);
  const api = await provisioner(adminPool);
  const { databaseName } = await api.createVisitorDatabase();
  const database = databases.get(databaseName);

  database.owner = 'someone_else';
  await assert.rejects(api.dropVisitorDatabase(databaseName), /not owned/);
  database.owner = 'postgres';
  database.is_template = true;
  await assert.rejects(api.dropVisitorDatabase(databaseName), /not owned/);
  database.is_template = false;
  database.marker = 'other-demo';
  await assert.rejects(api.dropVisitorDatabase(databaseName), /not claimed/);
  assert.equal(clients.at(-1).endCount, 1);
  database.marker = PLAYGROUND_OWNER;
  database.connections = 1;
  await assert.rejects(api.dropVisitorDatabase(databaseName), /open connections/);

  assert.equal(calls.some(([sql]) => sql.startsWith('DROP DATABASE ')), false);
  assert.equal(databases.has(databaseName), true);
  database.connections = 0;
  await api.dropVisitorDatabase(databaseName);
});

test('failed REVOKE or either GRANT after CREATE removes only the new clone', async (t) => {
  for (const failAt of ['REVOKE CONNECT ', ' TO agents_playground_app', ' TO agents_playground_naive']) {
    await t.test(failAt, async (subtest) => {
      const failure = new Error('permissions failed');
      const { adminPool, calls, databases, clients } = mockDatabase(subtest, { failAt, failure });
      const api = await provisioner(adminPool);
      await assert.rejects(api.createVisitorDatabase(), (err) => err === failure);
      const [, databaseName] = calls[1][0].match(/^CREATE DATABASE "([a-z0-9_]+)"/);
      assert.equal(databases.has(databaseName), false);
      assert.equal(clients.length, 1);
      assert.equal(clients[0].endCount, 1);
      assert.equal(calls.filter(([sql]) => sql === `DROP DATABASE "${databaseName}"`).length, 1);
    });
  }
});

test('failed cleanup leaves the clone recorded and rethrows the original provisioning error', async (t) => {
  const failure = new Error('naive GRANT failed');
  const dropFailure = new Error('DROP failed');
  const logs = [];
  t.mock.method(console, 'error', (...args) => logs.push(args));
  const { adminPool, calls, clients, databases } = mockDatabase(t, {
    failAt: ' TO agents_playground_naive', failure, failDrop: dropFailure,
  });
  const api = await provisioner(adminPool);
  await assert.rejects(api.createVisitorDatabase(), (err) => err === failure);
  const [, databaseName] = calls[1][0].match(/^CREATE DATABASE "([a-z0-9_]+)"/);
  assert.equal(databases.has(databaseName), true);
  assert.equal(failure.orphanedDatabaseName, databaseName);
  assert.equal(failure.cleanupError, dropFailure);
  assert.equal(clients[0].endCount, 1);
  assert.equal(logs[0][0], 'Partially provisioned visitor database requires cleanup');
  assert.deepEqual(logs[0][1], { databaseName, type: 'Error' });
  assert.match(JSON.stringify(logs), new RegExp(databaseName));
  assert.doesNotMatch(JSON.stringify(logs), /DROP failed/);
});

test('an existing-name collision never triggers DROP', async (t) => {
  const collision = Object.assign(new Error('duplicate database'), { code: '42P04' });
  const { adminPool, calls, clients, databases } = mockDatabase(t, { failCreate: collision });
  const api = await provisioner(adminPool);
  await assert.rejects(api.createVisitorDatabase(), (err) => err === collision);
  assert.equal(collision.orphanedDatabaseName, undefined);
  const [, databaseName] = calls[1][0].match(/^CREATE DATABASE "([a-z0-9_]+)"/);
  assert.equal(databases.has(databaseName), true);
  assert.equal(clients.length, 0);
  assert.equal(calls.some(([sql]) => sql.startsWith('DROP DATABASE ')), false);
});

test('startup cleanup drops multiple exact-format visitor databases and ignores malformed prefix matches', async (t) => {
  const first = visitorName('a');
  const second = visitorName('b');
  const invalidNames = [
    'agents_playground_visitor_short',
    `agents_playground_visitor_${'g'.repeat(32)}`,
  ];
  const extraDatabases = [
    [first, { owner: 'postgres', is_template: false, marker: PLAYGROUND_OWNER, connections: 0 }],
    [second, { owner: 'postgres', is_template: false, marker: PLAYGROUND_OWNER, connections: 0 }],
    ...invalidNames.map((name) => [name, { owner: 'postgres', is_template: false, marker: PLAYGROUND_OWNER, connections: 0 }]),
  ];
  const { adminPool, calls, databases } = mockDatabase(t, { extraDatabases });
  const api = await provisioner(adminPool);

  const result = await api.cleanupVisitorDatabases();
  assert.deepEqual(result, { deleted: [first, second], failed: [] });
  assert.equal(databases.has(first), false);
  assert.equal(databases.has(second), false);
  assert.ok(invalidNames.every((name) => databases.has(name)));
  assert.equal(databases.has(templateDatabaseName), true);
  const droppedNames = calls.filter(([sql]) => sql.startsWith('DROP DATABASE ')).map(([sql]) => sql.match(/"([^"]+)"/)[1]);
  assert.deepEqual(droppedNames.sort(), [first, second]);
  assert.ok(calls.some(([sql, params]) => sql.includes('FROM pg_database') && params[1] === templateDatabaseName));
  assert.ok(calls.every(([sql]) => !/DROP DATABASE .*FORCE|pg_terminate_backend/i.test(sql)));
});

test('startup cleanup explicitly excludes a configured template with a visitor prefix', async (t) => {
  const prefixedTemplate = 'agents_playground_visitor_template';
  const { adminPool, calls, databases } = mockDatabase(t, { templateName: prefixedTemplate });
  const api = await provisioner(adminPool, prefixedTemplate);

  assert.deepEqual(await api.cleanupVisitorDatabases(), { deleted: [], failed: [] });
  assert.equal(databases.has(prefixedTemplate), true);
  assert.equal(calls.some(([sql]) => sql.startsWith('DROP DATABASE ')), false);
});

test('startup cleanup refuses foreign owners, missing or foreign markers, and template candidates', async (t) => {
  const blocked = [
    { suffix: 'c', owner: 'other_role', marker: PLAYGROUND_OWNER, is_template: false, reason: /not owned/ },
    { suffix: 'd', owner: 'postgres', marker: null, is_template: false, reason: /not claimed/ },
    { suffix: 'e', owner: 'postgres', marker: 'another-playground', is_template: false, reason: /not claimed/ },
    { suffix: 'f', owner: 'postgres', marker: PLAYGROUND_OWNER, is_template: true, reason: /not owned/ },
  ];
  const extraDatabases = blocked.map(({ suffix, owner, marker, is_template }) => [
    visitorName(suffix), { owner, marker, is_template, connections: 0 },
  ]);
  const { adminPool, calls, databases } = mockDatabase(t, { extraDatabases });
  const api = await provisioner(adminPool);

  const result = await api.cleanupVisitorDatabases();
  assert.deepEqual(result.deleted, []);
  assert.deepEqual(result.failed.map(({ databaseName }) => databaseName), blocked.map(({ suffix }) => visitorName(suffix)));
  for (const [index, { suffix, reason }] of blocked.entries()) {
    assert.match(result.failed[index].error.message, reason);
    assert.equal(databases.has(visitorName(suffix)), true);
  }
  assert.equal(calls.some(([sql]) => sql.startsWith('DROP DATABASE ')), false);
});

test('startup cleanup removes eligible databases, reports open connections, and lets startup continue', async (t) => {
  const connected = visitorName('1');
  const removable = visitorName('2');
  const { adminPool, calls, databases } = mockDatabase(t, {
    extraDatabases: [
      [connected, { owner: 'postgres', is_template: false, marker: PLAYGROUND_OWNER, connections: 1 }],
      [removable, { owner: 'postgres', is_template: false, marker: PLAYGROUND_OWNER, connections: 0 }],
    ],
  });
  const api = await provisioner(adminPool);

  let startupContinued = false;
  const result = await api.cleanupVisitorDatabases();
  startupContinued = true;
  assert.equal(startupContinued, true);
  assert.deepEqual(result.deleted, [removable]);
  assert.equal(result.failed.length, 1);
  assert.equal(result.failed[0].databaseName, connected);
  assert.equal(result.failed[0].error.message, 'Playground visitor database still has open connections');
  assert.equal(databases.has(connected), true);
  assert.equal(databases.has(removable), false);
  assert.equal(calls.some(([sql]) => sql === `DROP DATABASE "${connected}"`), false);
  assert.equal(calls.some(([sql]) => sql === `DROP DATABASE "${removable}"`), true);
  assert.ok(calls.every(([sql]) => !/DROP DATABASE .*FORCE|pg_terminate_backend/i.test(sql)));
});

test('startup cleanup reports discovery failure without rejecting the startup caller', async (t) => {
  const discoveryError = new Error('catalog unavailable');
  const { adminPool } = mockDatabase(t, { failDiscovery: discoveryError });
  const api = await provisioner(adminPool);

  const result = await api.cleanupVisitorDatabases();
  assert.deepEqual(result.deleted, []);
  assert.equal(result.failed.length, 1);
  assert.equal(result.failed[0].databaseName, null);
  assert.equal(result.failed[0].error, discoveryError);
});
