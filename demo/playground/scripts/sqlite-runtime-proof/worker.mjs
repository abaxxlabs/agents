const PREFIX = 'SQLITE_RUNTIME_PROOF ';
const emit = (record) => process.stdout.write(`${PREFIX}${JSON.stringify(record)}\n`);
const checks = [];
const metrics = { samples: [] };
const startedAt = performance.now();
let context;
let helpers;
let queryPool;
let rawPool;
let masterKey;
let result;
let runtime;
let poolErrors = 0;
let stage = 'configuration';

function integer(name, fallback, minimum) {
  const input = process.env[name];
  if (input === undefined) return fallback;
  if (!/^\d{1,8}$/.test(input) || !Number.isSafeInteger(Number(input)) || Number(input) < minimum) {
    throw new Error('Invalid proof cycle configuration');
  }
  return Number(input);
}

function connectionString(name) {
  const value = process.env[name];
  const url = new URL(value);
  if (!['postgres:', 'postgresql:'].includes(url.protocol) || !url.username || !url.pathname.slice(1)) {
    throw new Error('Invalid proof database configuration');
  }
  return value;
}

function previousAgents(action) {
  const parsed = JSON.parse(process.env.PROOF_PREVIOUS_AGENTS ?? '[]');
  if (!Array.isArray(parsed) || parsed.length > 100 || parsed.some((did) =>
    typeof did !== 'string' || !/^did:key:z[1-9A-HJ-NP-Za-km-z]{20,100}$/.test(did))
    || new Set(parsed).size !== parsed.length || (action === 'restart' && parsed.length < 2)) {
    throw new Error('Invalid previous public identities');
  }
  return parsed;
}

try {
  const action = process.argv[2];
  if (!['run', 'hold', 'restart'].includes(action)) throw new Error('Unknown proof action');
  const queryUrl = connectionString('PROOF_DATABASE_URL');
  const rawUrl = connectionString('PROOF_RAW_DATABASE_URL');
  if (!/^[a-fA-F0-9]{64}$/.test(process.env.PROOF_MASTER_KEY ?? '')) throw new Error('Invalid master key');
  masterKey = Buffer.from(process.env.PROOF_MASTER_KEY, 'hex');
  delete process.env.PROOF_MASTER_KEY;
  const cycles = integer('PROOF_CYCLES', 200, 1);
  const warmup = integer('PROOF_WARMUP', 20, 0);
  const previous = previousAgents(action);
  stage = 'pool-loading';
  const { default: pg } = await import('pg');
  const options = { connectionTimeoutMillis: 3000, statement_timeout: 5000 };
  queryPool = new pg.Pool({ ...options, connectionString: queryUrl, max: 2,
    application_name: 'sqlite-runtime-proof-query' });
  rawPool = new pg.Pool({ ...options, connectionString: rawUrl, max: 1,
    application_name: 'sqlite-runtime-proof-raw' });
  for (const pool of [queryPool, rawPool]) pool.on('error', () => { poolErrors++; });
  stage = 'sdk-loading';
  helpers = await import('./runtime.mjs');
  const scenarios = await import('./scenarios.mjs');
  stage = 'runtime-provenance';
  runtime = helpers.runtimeDescription();
  context = { checks, metrics, emit, startedAt, queryPool, rawPool, masterKey, cycles, warmup,
    runtime, previousAgents: previous, manager: helpers.createRuntimeManager(queryPool, queryUrl) };
  metrics.configuration = { cycles, warmup, sampleInterval: 25, queryPoolMax: 2, rawPoolMax: 1,
    connectionTimeoutMillis: 3000, statementTimeoutMillis: 5000, forcedGc: false };
  stage = action;
  const actions = { run: scenarios.runScenarios, hold: scenarios.holdScenarios, restart: scenarios.restartScenarios };
  await actions[action](context);
  result = { type: 'result', protocolVersion: 1, action, status: 'PASS', checks, metrics, runtime };
} catch (error) {
  checks.push({ name: 'worker-execution', status: 'FAIL', stage,
    error: helpers ? helpers.safeError(error) : { category: 'configuration-or-load-failed', code: 'REDACTED' } });
  result = { type: 'result', status: 'FAIL', checks, metrics,
    runtime: runtime ?? (helpers ? helpers.runtimeDescription() : { node: process.version, stage }) };
  process.exitCode = 1;
} finally {
  if (context) {
    try { await context.manager.closeAll(); }
    catch { checks.push({ name: 'worker-runtime-cleanup', status: 'FAIL' }); }
    metrics.finalBeforePoolClose = await helpers.snapshot(context, 'worker-cleanup');
    const summary = context.manager.summary();
    checks.push({ name: 'worker-runtime-cleanup', status: summary.live === 0
      && summary.storesCreated === summary.storesClosed && summary.callerOwnedBuffersZeroed ? 'PASS' : 'FAIL',
    ...summary });
  }
  for (const [name, pool] of [['query', queryPool], ['raw', rawPool]]) {
    if (!pool) continue;
    try { await pool.end(); checks.push({ name: `worker-${name}-pool-closed`, status: 'PASS' }); }
    catch { checks.push({ name: `worker-${name}-pool-closed`, status: 'FAIL' }); }
  }
  masterKey?.fill(0);
  checks.push({ name: 'worker-master-buffer-overwritten',
    status: !masterKey || masterKey.every((byte) => byte === 0) ? 'PASS' : 'FAIL', allocated: !!masterKey });
  checks.push({ name: 'worker-no-idle-pool-errors', status: poolErrors === 0 ? 'PASS' : 'FAIL', count: poolErrors });
  if (context) metrics.finalAfterPoolClose = await helpers.snapshot(context, 'worker-pools-closed');
  if (result) {
    if (checks.some((entry) => entry.status === 'FAIL')) { result.status = 'FAIL'; process.exitCode = 1; }
    emit(result);
  }
}
