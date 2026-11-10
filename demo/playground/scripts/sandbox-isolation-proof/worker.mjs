import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import pg from 'pg';
import { createRuntimeManager, runtimeDescription } from '../sqlite-runtime-proof/runtime.mjs';
import { createExecutors, SANDBOX_A, SANDBOX_B } from './executor.mjs';
import { runScenarios } from './scenarios.mjs';

const checks = [];
const events = [];
const pools = {};
const managers = {};
const runtimes = {};
const masterKey = Buffer.from(process.env.ISOLATION_MASTER_KEY ?? '', 'hex');
const report = { protocol: 1, status: 'FAIL', checks, events };
let stage = 'runtime-provenance';
try {
  assert.equal(process.versions.node.split('.')[0], '22', 'Use the actual Node 22 runtime image');
  assert.equal(masterKey.length, 32);
  report.runtime = runtimeDescription();
  assert.equal(report.runtime.sqliteDriver, 'better-sqlite3');
  assert.equal(report.runtime.betterSqlite3?.probe, 'PASS');
  assert.equal(report.runtime.uid, 1000);
  assert.equal(report.runtime.sdk?.packageRoot, '/app');
  report.runtimeModuleSha256 = createHash('sha256').update(await readFile(new URL('../sqlite-runtime-proof/runtime.mjs', import.meta.url))).digest('hex');
  report.imageModules = {};
  for (const module of ['../../src/direct-sql-policy.mjs', '../migration-config.mjs']) {
    report.imageModules[module] = createHash('sha256').update(await readFile(new URL(module, import.meta.url))).digest('hex');
  }
  stage = 'process-pools';
  for (const role of ['query', 'raw', 'control']) {
    const connectionString = process.env[`ISOLATION_${role.toUpperCase()}_URL`];
    assert.ok(connectionString, `Missing ${role} pool configuration`);
    pools[role] = new pg.Pool({ connectionString, max: 1, connectionTimeoutMillis: 3000,
      statement_timeout: 5000, application_name: `sandbox-isolation-proof-${role}` });
    pools[role].on('error', () => { report.poolError = true; });
  }
  const executors = createExecutors({ queryPool: pools.query, rawPool: pools.raw,
    controlPool: pools.control, events });
  stage = 'real-sdk-runtimes';
  for (const [label, sandbox] of [['A', SANDBOX_A], ['B', SANDBOX_B]]) {
    managers[label] = createRuntimeManager(executors.queryAdapter(sandbox), process.env.ISOLATION_QUERY_URL);
    runtimes[label] = await managers[label].create(masterKey, label);
    await runtimes[label].populate();
    assert.equal(runtimes[label].callerOwned, true);
  }
  stage = 'isolation-matrix';
  const evidence = await runScenarios({ executors, queryPool: pools.query, rawPool: pools.raw,
    controlPool: pools.control, managers, runtimes, checks, events });
  report.evidence = evidence;
  for (const criterion of ['privateOperations', 'hostileSql', 'physicalReuse', 'rowPolicies', 'protectedBehavior']) {
    assert.equal(evidence?.acceptance?.[criterion], true, `Missing acceptance evidence: ${criterion}`);
  }
  assert.ok(evidence.matrix?.length > 0);
  assert.ok(checks.length > 0 && checks.every((check) => check.status === 'PASS'));
  assert.ok(events.some((event) => event.outcome === 'commit'));
  assert.ok(events.some((event) => event.outcome === 'rollback'));
  assert.ok(!report.poolError);
  report.status = 'PASS';
} catch (error) {
  report.failure = { stage, name: error?.name ?? 'Error',
    code: /^[A-Z0-9_]{3,40}$/.test(error?.code ?? '') ? error.code : 'CHECK_FAILED',
    source: /(?:worker|scenarios|executor)\.mjs:\d+/.exec(error?.stack ?? '')?.[0],
    check: typeof error?.check === 'string' ? error.check : undefined };
} finally {
  const cleanup = [];
  for (const [label, manager] of Object.entries(managers)) {
    try {
      await manager.closeAll();
      const summary = manager.summary();
      assert.equal(summary.live, 0);
      assert.equal(summary.storesCreated, summary.storesClosed);
      cleanup.push({ resource: `runtime-${label}`, status: 'PASS', summary });
    } catch { cleanup.push({ resource: `runtime-${label}`, status: 'FAIL' }); }
  }
  for (const [role, pool] of Object.entries(pools)) {
    try {
      await pool.end();
      assert.equal(pool.totalCount, 0);
      cleanup.push({ resource: `pool-${role}`, status: 'PASS', total: pool.totalCount });
    } catch { cleanup.push({ resource: `pool-${role}`, status: 'FAIL' }); }
  }
  masterKey.fill(0);
  report.cleanup = cleanup;
  if (report.poolError || cleanup.some((item) => item.status !== 'PASS')) report.status = 'FAIL';
}
console.log(`SANDBOX_ISOLATION_PROOF ${JSON.stringify(report)}`);
if (report.status !== 'PASS') process.exitCode = 1;
