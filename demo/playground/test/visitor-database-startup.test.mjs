import assert from 'node:assert/strict';
import test from 'node:test';
import { cleanupVisitorDatabasesAtStartup } from '../src/visitor-database-startup.mjs';

test('startup cleanup reports partial failures and returns so startup can proceed', async () => {
  const order = [];
  const failedDatabase = `agents_playground_visitor_${'d'.repeat(32)}`;
  const cleanupError = new Error('database still has connections');
  const logs = [];
  const result = await cleanupVisitorDatabasesAtStartup({
    adminPool: { id: 'admin-pool' },
    adminDatabaseUrl: 'postgres://admin/postgres',
    appDatabaseUrl: 'postgres://app/playground',
    templateDatabaseName: 'playground',
    logger: {
      info(...args) { order.push('summary'); logs.push(['info', ...args]); },
      warn(...args) { order.push('warning'); logs.push(['warn', ...args]); },
    },
    createProvisioner: async (options) => {
      order.push('provisioner');
      assert.equal(options.adminPool.id, 'admin-pool');
      assert.equal(options.templateDatabaseName, 'playground');
      return {
        async cleanupVisitorDatabases() {
          order.push('cleanup');
          return {
            deleted: ['agents_playground_visitor_12345678'],
            failed: [{ databaseName: failedDatabase, error: cleanupError }],
          };
        },
      };
    },
  });

  assert.deepEqual(order, ['provisioner', 'cleanup', 'summary', 'warning']);
  assert.deepEqual(result.deleted, ['agents_playground_visitor_12345678']);
  assert.equal(result.failed[0].databaseName, failedDatabase);
  assert.equal(logs[0][1], 'Visitor database startup cleanup completed');
  assert.deepEqual(logs[0][2], { deletedCount: 1, failedCount: 1 });
  assert.equal(logs[1][1], 'Visitor database startup cleanup could not remove a candidate; continuing startup');
  assert.deepEqual(logs[1][2], { databaseName: failedDatabase, type: 'Error' });
  assert.match(JSON.stringify(logs), new RegExp(failedDatabase));
  assert.doesNotMatch(JSON.stringify(logs), /database still has connections/);
});

test('startup continues when provisioner initialization fails', async () => {
  const initializationError = new Error('administrative connection unavailable');
  const warnings = [];
  const result = await cleanupVisitorDatabasesAtStartup({
    adminPool: {},
    adminDatabaseUrl: 'postgres://admin/postgres',
    appDatabaseUrl: 'postgres://app/playground',
    templateDatabaseName: 'playground',
    logger: { info() {}, warn(...args) { warnings.push(args); } },
    createProvisioner: async () => { throw initializationError; },
  });

  assert.deepEqual(result.deleted, []);
  assert.equal(result.failed[0].error, initializationError);
  assert.match(warnings[0][0], /continuing startup/);
});
