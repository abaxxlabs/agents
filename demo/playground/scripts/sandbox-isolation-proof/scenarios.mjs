import { createHash } from 'node:crypto';
import { SANDBOX_A, SANDBOX_B } from './executor.mjs';
import { BASE_SQL, BROAD_SQL } from '../sqlite-runtime-proof/runtime.mjs';

const READ = 'SELECT sandbox_id, id, instrument, quantity, price, counterparty FROM public.orders_plaintext ORDER BY id';
const SNAPSHOT = 'SELECT proof_private.snapshot() AS snapshot';
const SETTINGS = "SELECT pg_backend_pid() AS pid, current_user AS role, current_setting('proof.sandbox_token', true) AS token, current_setting('search_path') AS search_path, current_setting('statement_timeout') AS statement_timeout, current_setting('lock_timeout') AS lock_timeout, current_setting('idle_in_transaction_session_timeout') AS idle_timeout";
function canonical(value, key = '') {
  if (Array.isArray(value)) return value.map((item) => canonical(item));
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map((name) => [name, canonical(value[name], name)]));
  return key === 'price' && typeof value === 'string' && /^\d+(?:\.\d+)?$/.test(value) ? Number(value) : value;
}
const digest = (value) => createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex');
const sqlHash = (sql) => createHash('sha256').update(sql).digest('hex');
const rowsOf = (result) => Array.isArray(result) ? result : result?.rows;
const stateOf = (rows, sandbox) => rows.filter((row) => row.sandbox_id === sandbox);

/** Exercises policy, real SDK runtimes, and PostgreSQL against the disposable fixture. */
export async function runScenarios({ executors, queryPool, rawPool, controlPool, managers, runtimes, checks, events }) {
  const matrix = [];
  const acceptance = {};
  function assert(name, passed, details = {}) {
    checks.push({ name, status: passed ? 'PASS' : 'FAIL', ...details });
    if (!passed) throw new Error(`Isolation assertion failed: ${name}`);
  }
  async function probe(name, layer, sql, expected, operation, predicate = () => true) {
    let result;
    let error;
    try { result = await operation(); } catch (caught) { error = caught; }
    const observed = error ? (error.code ?? 'UNCLASSIFIED_ERROR') : 'accepted';
    let passed = expected === observed;
    if (passed && !error) {
      try { passed = !!predicate(result); } catch { passed = false; }
    }
    const components = result?.plaintext && result?.encrypted ? [
      { role: 'raw', rowCount: result.plaintext.length }, { role: 'query', rowCount: result.encrypted.length },
    ] : undefined;
    const entry = { name, layer, sql, expected, observed,
      ...(error ? { sqlstate: /^[0-9A-Z]{5}$/.test(error.code ?? '') ? error.code : null }
        : { affectedRows: components ? components.reduce((sum, item) => sum + item.rowCount, 0)
          : result?.rowCount ?? rowsOf(result)?.length ?? 0 }), ...(components ? { components } : {}) };
    matrix.push(entry);
    assert(name, passed, entry);
    return result;
  }
  const snapshot = async () => (await controlPool.query(SNAPSHOT)).rows[0].snapshot;
  const original = await snapshot();
  const protectedFingerprint = digest(original.orders);
  const aOriginal = stateOf(original.privateRows, SANDBOX_A);
  const bOriginal = stateOf(original.privateRows, SANDBOX_B);
  assert('fixture has overlapping ids and distinct private markers', aOriginal.length === 2 && bOriginal.length === 2
    && aOriginal.every((row, index) => row.id === bOriginal[index].id && row.counterparty === 'A-private')
    && bOriginal.every((row) => row.counterparty === 'B-private'));
  for (const role of ['proof_query', 'proof_raw']) {
    const facts = original.roles.find((item) => item.name === role);
    assert(`${role} has no privileged database identity`, facts && !facts.superuser && !facts.bypassRls
      && !facts.owner && !facts.createDb && !facts.createRole, { role });
  }
  assert('plaintext row policy is forced with symmetric write check', original.policies.some((policy) =>
    policy.table === 'orders_plaintext' && policy.enabled && policy.forced
    && policy.using?.includes('current_sandbox') && policy.withCheck?.includes('current_sandbox')));
  const baseline = {};
  const clean = async (role, pool, name) => {
    const after = (await pool.query(SETTINGS)).rows[0];
    const safeSettings = ({ token, ...settings }) => ({ ...settings, tokenEmpty: !token });
    assert(name, !after.token && after.pid === baseline[role].pid
      && ['role', 'search_path', 'statement_timeout', 'lock_timeout', 'idle_timeout'].every((key) => after[key] === baseline[role][key]),
    { before: safeSettings(baseline[role]), after: safeSettings(after) });
    return after;
  };
  for (const [role, pool] of [['query', queryPool], ['raw', rawPool]]) {
    baseline[role] = (await pool.query(SETTINGS)).rows[0];
    assert(`${role} starts without a context token`, !baseline[role].token);
    await probe(`${role} cannot read private rows outside scoped transaction`, 'postgres-role + context', READ,
      '42501', async () => {
        const client = await pool.connect();
        try { return await client.query(READ); }
        finally { client.release(); }
      });
  }
  const ownRows = (result, sandbox, expected) => {
    const rows = rowsOf(result);
    return digest(rows) === digest(expected) && rows.every((row) => row.sandbox_id === sandbox);
  };
  const bIntact = async (name) => {
    const current = await snapshot();
    assert(name, digest(stateOf(current.privateRows, SANDBOX_B)) === digest(bOriginal)
      && digest(current.orders) === protectedFingerprint);
  };
  const db = (role, sandbox, sql, params) => executors.withSandbox(role, sandbox, (client) => client.query(sql, params));
  for (const [label, sandbox, expected] of [['A', SANDBOX_A, aOriginal], ['B', SANDBOX_B, bOriginal]]) {
    await probe(`qualified plaintext read is scoped to ${label}`, 'sql-policy + postgres-rls', READ, 'accepted',
      () => executors.raw(sandbox, READ), (result) => ownRows(result, sandbox, expected));
  }
  const crossRead = `SELECT * FROM public.orders_plaintext WHERE sandbox_id = '${SANDBOX_B}'`;
  await probe('A explicit B read returns zero rows', 'postgres-rls', crossRead, 'accepted',
    () => executors.raw(SANDBOX_A, crossRead), (result) => rowsOf(result).length === 0);
  const update = "UPDATE public.orders_plaintext SET instrument = 'A-changed', quantity = 77, price = 99, counterparty = 'A-updated' WHERE id = 1";
  await probe('A update affects exactly its own row', 'sql-policy + postgres-rls', update, 'accepted',
    () => executors.raw(SANDBOX_A, update), (result) => result.rowCount === 1);
  const updated = stateOf((await snapshot()).privateRows, SANDBOX_A);
  assert('A update changes its selected row', updated.length === 2 && updated[0].instrument === 'A-changed'
    && Number(updated[0].quantity) === 77 && Number(updated[0].price) === 99 && updated[0].counterparty === 'A-updated');
  await bIntact('A update leaves B and full encrypted fixture unchanged');
  const crossUpdate = `UPDATE public.orders_plaintext SET quantity = 0 WHERE sandbox_id = '${SANDBOX_B}'`;
  await probe('A explicit B update affects zero rows', 'postgres-rls', crossUpdate, 'accepted',
    () => executors.raw(SANDBOX_A, crossUpdate), (result) => result.rowCount === 0);
  const remove = 'DELETE FROM public.orders_plaintext WHERE id = 2';
  await probe('A delete affects exactly its own row', 'sql-policy + postgres-rls', remove, 'accepted',
    () => executors.raw(SANDBOX_A, remove), (result) => result.rowCount === 1);
  assert('A delete removes only its selected row', stateOf((await snapshot()).privateRows, SANDBOX_A).length === 1);
  const crossDelete = `DELETE FROM public.orders_plaintext WHERE sandbox_id = '${SANDBOX_B}'`;
  await probe('A explicit B delete affects zero rows', 'postgres-rls', crossDelete, 'accepted',
    () => executors.raw(SANDBOX_A, crossDelete), (result) => result.rowCount === 0);
  await bIntact('A delete leaves B and full encrypted fixture unchanged');
  const beforeReset = await snapshot();
  assert('reset runs with an enabled rejecting BEFORE TRUNCATE guard', beforeReset.truncateGuardEnabled === true);
  await probe('reset reseeds A without truncating shared state', 'trusted-control',
    'SELECT proof_private.reset_sandbox($1::uuid)', 'accepted', () => executors.reset(SANDBOX_A));
  const afterReset = await snapshot();
  const deletedByReset = afterReset.deleteEvents.slice(beforeReset.deleteEvents.length);
  const expectedResetDeletes = stateOf(beforeReset.privateRows, SANDBOX_A).map(({ sandbox_id, id }) => ({ sandbox_id, id }));
  assert('reset emits only selected sandbox row DELETE events', digest(deletedByReset) === digest(expectedResetDeletes)
    && digest(afterReset.deleteEvents.slice(0, beforeReset.deleteEvents.length)) === digest(beforeReset.deleteEvents),
  { deletedRows: deletedByReset.length, sandbox: SANDBOX_A, truncateGuardEnabled: afterReset.truncateGuardEnabled });
  assert('A reset restores exactly A original rows', digest(stateOf(afterReset.privateRows, SANDBOX_A)) === digest(aOriginal));
  await bIntact('A reset leaves B and full encrypted fixture unchanged');
  acceptance.privateOperations = true;

  const sdkRows = {};
  for (const label of ['A', 'B']) {
    const runtime = runtimes[label];
    sdkRows[label] = await probe(`${label} real SDK narrow credential allows base projection`, 'sdk', BASE_SQL, 'accepted',
      () => runtime.query({ sql: BASE_SQL }), (result) => result.rows.length === 2
        && result.rows.every((row) => Object.keys(row).sort().join(',') === 'id,instrument,price,quantity'));
    await probe(`${label} narrow credential denies broader projection`, 'sdk', BROAD_SQL, 'SCOPE_VIOLATION',
      () => runtime.query({ sql: BROAD_SQL }));
    await probe(`${label} identical SQL succeeds with broader signed credential`, 'sdk', BROAD_SQL, 'accepted',
      () => runtime.query({ sql: BROAD_SQL, credential: runtime.broadCredential }), (result) =>
        result.rows.length === 2 && result.rows.every((row, index) => typeof row.counterparty === 'string'
          && Object.entries(sdkRows[label].rows[index]).every(([key, value]) => row[key] === value)));
  }
  assert('SDK visitors read the same shared protected fixture', digest(sdkRows.A.rows) === digest(sdkRows.B.rows)
    && managers.A !== managers.B && runtimes.A.storage !== runtimes.B.storage && runtimes.A.agent.did !== runtimes.B.agent.did);
  const rawSnapshots = {};
  for (const [label, sandbox, expected] of [['A', SANDBOX_A, aOriginal], ['B', SANDBOX_B, bOriginal]]) {
    const projected = expected.map(({ id, instrument, price, counterparty }) => ({ id, instrument, price, counterparty }));
    rawSnapshots[label] = await probe(`${label} rawBytes contains only its private rows`, 'postgres-rls + encrypted-read',
      [{ role: 'raw', sql: 'SELECT id, instrument, price, counterparty FROM public.orders_plaintext ORDER BY id LIMIT 4' },
        { role: 'query', sql: 'SELECT id, instrument, price, counterparty FROM public.orders ORDER BY id LIMIT 4' }], 'accepted',
      () => executors.rawBytes(sandbox), (result) => digest(result.plaintext) === digest(projected)
        && result.encrypted.length === 2 && result.encrypted.every((row, index) => typeof row.price === 'string'
          && row.price.startsWith('\\x') && typeof row.counterparty === 'string' && row.counterparty.startsWith('\\x')
          && row.price !== sdkRows[label].rows[index].price));
  }
  assert('rawBytes encrypted fixture is shared and unchanged', digest(rawSnapshots.A.encrypted) === digest(rawSnapshots.B.encrypted));
  const encryptedProjection = original.orders.map(({ id, instrument, price, counterparty }) => ({ id, instrument, price, counterparty }));
  assert('rawBytes ciphertext equals the entire canonical encrypted fixture projection', digest(rawSnapshots.A.encrypted) === digest(encryptedProjection));
  await bIntact('rawBytes does not mutate B or the full encrypted fixture');
  acceptance.protectedBehavior = true;
  const forbidden = [
    ['private registry', 'SELECT * FROM proof_private.sandboxes'],
    ['private signing key', 'SELECT * FROM proof_private.context_secret'],
    ['private DELETE observer', 'SELECT * FROM proof_private.delete_events'],
    ['shared table truncation', 'TRUNCATE public.orders_plaintext'],
    ['privileged role catalog', 'SELECT * FROM pg_catalog.pg_authid'],
    ['context signer', `SELECT proof_private.issue_context('${SANDBOX_A}'::uuid, pg_backend_pid(), txid_current()::text, current_user::text)`],
    ['sandbox reset', `SELECT proof_private.reset_sandbox('${SANDBOX_B}'::uuid)`],
    ['private snapshot', SNAPSHOT],
    ['test-only RLS oracle', `SELECT proof_private.probe_with_check('${SANDBOX_A}'::uuid, '${SANDBOX_B}'::uuid)`],
    ['role escalation', 'SET ROLE proof_control'],
    ['session identity escalation', 'SET SESSION AUTHORIZATION proof_control'],
    ['private function in subquery', 'SELECT (SELECT proof_private.snapshot())'],
  ];
  for (const role of ['query', 'raw']) {
    for (const [name, sql] of forbidden) {
      if (role === 'raw') await probe(`${role} parser rejects ${name}`, 'sql-policy', sql, 'SQL_POLICY_REJECTED',
        () => executors.raw(SANDBOX_A, sql));
      await probe(`${role} database denies ${name} without parser`, 'postgres-role', sql, '42501',
        () => db(role, SANDBOX_A, sql));
    }
    const reassign = `UPDATE public.orders_plaintext SET sandbox_id = '${SANDBOX_B}' WHERE id = 1`;
    if (role === 'raw') await probe('parser rejects sandbox reassignment', 'sql-policy', reassign, 'SQL_POLICY_REJECTED',
      () => executors.raw(SANDBOX_A, reassign));
    await probe(`${role} cannot update sandbox ownership`, 'postgres-column-grant', reassign, '42501',
      () => db(role, SANDBOX_A, reassign));
    const insert = `INSERT INTO public.orders_plaintext (sandbox_id,id,instrument,quantity,price,counterparty) VALUES ('${SANDBOX_B}',3,'forged',1,1,'forged')`;
    await probe(`${role} cannot insert another sandbox row`, 'postgres-role', insert, '42501',
      () => db(role, SANDBOX_A, insert));
    const subquery = `SELECT stolen FROM (SELECT (SELECT counterparty FROM public.orders_plaintext WHERE sandbox_id = '${SANDBOX_B}' LIMIT 1) AS stolen) AS nested`;
    if (role === 'raw') await probe('parser rejects derived relation subquery', 'sql-policy', subquery, 'SQL_POLICY_REJECTED',
      () => executors.raw(SANDBOX_A, subquery));
    await probe(`${role} subquery cannot expose B`, role === 'raw' ? 'postgres-rls' : 'postgres-role', subquery,
      role === 'raw' ? 'accepted' : '42501', () => db(role, SANDBOX_A, subquery),
      (result) => result.rows.length === 1 && result.rows[0].stolen === null);
    const functionSql = "SELECT set_config('proof.sandbox_token', 'forged', true) FROM public.orders_plaintext";
    if (role === 'raw') await probe('parser rejects context-mutating function', 'sql-policy', functionSql, 'SQL_POLICY_REJECTED',
      () => executors.raw(SANDBOX_A, functionSql));
  }
  acceptance.hostileSql = true;
  const policyProbe = 'SELECT proof_private.probe_with_check($1::uuid, $2::uuid) AS probe';
  const writeCheck = await probe('test-only nonowner oracle exercises real INSERT WITH CHECK', 'postgres-rls-test-only-oracle', policyProbe,
    'accepted', () => controlPool.query(policyProbe, [SANDBOX_A, SANDBOX_B]), (result) =>
      result.rows[0].probe.crossState === '42501' && result.rows[0].probe.ownInsert === true
      && result.rows[0].probe.ownDelete === true);
  matrix.push({ name: 'test-only cross-sandbox INSERT fails actual WITH CHECK', layer: 'postgres-rls-test-only-oracle',
    sql: "INSERT INTO public.orders_plaintext VALUES (other_sandbox, 90, 'PROBE', 1, 1, 'probe')",
    expected: '42501', observed: writeCheck.rows[0].probe.crossState, sqlstate: writeCheck.rows[0].probe.crossState, affectedRows: 0 });
  await bIntact('WITH CHECK oracle leaves B and encrypted fixture unchanged');
  acceptance.rowPolicies = true;

  let retainedToken;
  await executors.withSandbox('raw', SANDBOX_A, async (client) => {
    retainedToken = (await client.query("SELECT current_setting('proof.sandbox_token') AS token")).rows[0].token;
    assert('signed context is retained only in transaction memory', typeof retainedToken === 'string' && retainedToken.length > 64);
  });
  const forgery = ["SELECT set_config('proof.sandbox_token', $1, true)", 'SELECT proof_guard.current_sandbox()'];
  const currentContext = "SELECT pg_backend_pid() AS pid, txid_current()::text AS xid, session_user::text AS session_user, proof_guard.current_sandbox() AS sandbox, current_setting('proof.sandbox_token') AS token";
  for (const role of ['raw', 'query']) {
    for (const [name, value] of [['forged custom GUC', 'forged'], ['prior transaction token replay', retainedToken]]) {
      await probe(`${role} ${name} cannot establish authenticated context`, 'postgres-context', forgery.map((sql) => ({ role, sql })), '42501',
        () => executors.withSandbox(role, SANDBOX_B, async (client) => {
          await client.query("SELECT set_config('proof.sandbox_token', $1, true)", [value]);
          return client.query('SELECT proof_guard.current_sandbox()');
        }));
    }
    await probe(`${role} invalid signature with current context cannot establish authenticated context`, 'postgres-context',
      [currentContext, ...forgery].map((sql) => ({ role, sql })), '42501',
      () => executors.withSandbox(role, SANDBOX_B, async (client) => {
        const context = (await client.query(currentContext)).rows[0];
        const parts = typeof context.token === 'string'
          ? /^([^:]+):(\d+):(\d+):([^:]+):([0-9a-f]{64})$/.exec(context.token) : null;
        assert(`${role} original signed context matches current sandbox PID XID and session user`, parts !== null
          && context.sandbox === SANDBOX_B && parts[1] === context.sandbox && parts[2] === String(context.pid)
          && parts[3] === context.xid && parts[4] === context.session_user);
        const signature = `${parts[5][0] === '0' ? '1' : '0'}${parts[5].slice(1)}`;
        const token = `${context.sandbox}:${context.pid}:${context.xid}:${context.session_user}:${signature}`;
        await client.query(forgery[0], [token]);
        return client.query(forgery[1]);
      }));
  }
  retainedToken = null;
  const poison = "SELECT set_config('proof.sandbox_token',current_setting('proof.sandbox_token'),false), set_config('search_path','pg_catalog',false), set_config('statement_timeout','9000',false), set_config('lock_timeout','8000',false), set_config('idle_in_transaction_session_timeout','7000',false)";
  for (const [role, pool] of [['raw', rawPool], ['query', queryPool]]) {
    for (const rollback of [false, true]) {
      const sql = (rollback ? [poison, 'SELECT 1 / 0'] : [poison]).map((statement) => ({ role, sql: statement }));
      await probe(`${role} persistent poisoning on ${rollback ? 'rollback' : 'commit'}`, 'postgres-session-defense',
        sql, rollback ? '22012' : 'accepted', () => executors.withSandbox(role, SANDBOX_A, async (client) => {
          const result = await client.query(poison);
          return rollback ? client.query('SELECT 1 / 0') : result;
        }));
      await clean(role, pool, `${role} sanitizes persistent GUC changes after ${rollback ? 'rollback' : 'commit'}`);
      await probe(`${role} B receives clean authenticated context after poisoning`, 'postgres-context',
        'SELECT proof_guard.current_sandbox() AS sandbox', 'accepted',
        () => db(role, SANDBOX_B, 'SELECT proof_guard.current_sandbox() AS sandbox'),
        (result) => result.rows[0].sandbox === SANDBOX_B);
    }
  }
  for (let cycle = 0; cycle < 3; cycle++) {
    for (const [label, sandbox, originalRows] of [['A', SANDBOX_A, aOriginal], ['B', SANDBOX_B, bOriginal]]) {
      await probe(`${label} alternating reuse scoped read ${cycle}`, 'postgres-rls', READ, 'accepted',
        () => executors.raw(sandbox, READ), (result) => ownRows(result, sandbox, originalRows));
      await probe(`${label} parser rejection before checkout ${cycle}`, 'sql-policy', 'SELECT pg_sleep(1)', 'SQL_POLICY_REJECTED',
        () => executors.raw(sandbox, 'SELECT pg_sleep(1)'));
      await probe(`${label} SDK rejection during reuse ${cycle}`, 'sdk', BROAD_SQL, 'SCOPE_VIOLATION',
        () => runtimes[label].query({ sql: BROAD_SQL }));
      for (const role of ['raw', 'query']) {
        await probe(`${role} ${label} real transaction abort ${cycle}`, 'postgres-execution', 'SELECT 1 / 0', '22012',
          () => db(role, sandbox, 'SELECT 1 / 0'));
      }
    }
    await probe(`B survives failed operations ${cycle}`, 'postgres-rls', READ, 'accepted',
      () => executors.raw(SANDBOX_B, READ), (result) => ownRows(result, SANDBOX_B, bOriginal));
    await probe(`B SDK query survives failed transactions ${cycle}`, 'sdk', BASE_SQL, 'accepted',
      () => runtimes.B.query({ sql: BASE_SQL }), (result) => digest(result.rows) === digest(sdkRows.B.rows));
  }
  const reuse = {};
  for (const [role, pool] of [['raw', rawPool], ['query', queryPool]]) {
    const after = await clean(role, pool, `${role} token timeouts search path and role never leak across reuse`);
    const roleEvents = events.filter((event) => event.role === role);
    const pids = [...new Set(roleEvents.map((event) => event.pid))];
    assert(`${role} reused one physical connection across both visitors and failures`, pids.length === 1
      && pids[0] === baseline[role].pid && after.pid === baseline[role].pid
      && roleEvents.every((event) => event.initialContextEmpty && event.cleanupContextEmpty && !event.discarded)
      && [SANDBOX_A, SANDBOX_B].every((sandbox) => roleEvents.some((event) => event.sandbox === sandbox && event.outcome === 'commit')
        && roleEvents.some((event) => event.sandbox === sandbox && event.outcome === 'rollback')));
    reuse[role] = { pid: after.pid, successful: roleEvents.filter((event) => event.outcome === 'commit').length,
      rolledBack: roleEvents.filter((event) => event.outcome === 'rollback').length, residualToken: false,
      role: after.role, statementTimeout: after.statement_timeout, lockTimeout: after.lock_timeout, idleTimeout: after.idle_timeout };
  }
  acceptance.physicalReuse = true;
  for (const label of ['A', 'B']) {
    const runtime = runtimes[label];
    const records = await runtime.scope.auditLoggerInstance.export();
    const chain = await runtime.scope.auditLoggerInstance.verifyAuditChain();
    assert(`${label} private SQLite audit includes success and scope rejections`, records.length >= 6
      && records.every((record) => record.agentDid === runtime.agent.did)
      && records.some((record) => record.status === 'success' && record.queryHash === sqlHash(BASE_SQL) && record.rowCount === 2)
      && records.some((record) => record.status === 'success' && record.queryHash === sqlHash(BROAD_SQL) && record.rowCount === 2)
      && records.some((record) => record.status === 'rejected' && record.reasonCode === 'SCOPE_VIOLATION'
        && record.queryHash === sqlHash(BROAD_SQL))
      && chain.ok && chain.partial === false && chain.totalRecords === records.length,
    { auditRows: records.length, fullChain: chain.ok });
  }
  const final = await snapshot();
  assert('entire encrypted fixture and both private sandboxes remain intact',
    digest(final.orders) === protectedFingerprint && digest(final.privateRows) === digest(original.privateRows),
    { beforeFingerprint: protectedFingerprint, afterFingerprint: digest(final.orders) });
  return { matrix, acceptance, reuse,
    state: { beforeFingerprint: protectedFingerprint, afterFingerprint: digest(final.orders), privateFixtureRestored: true,
      policyFacts: final.policies, roleFacts: final.roles },
    decision: { privilegedControl: 'Disposable fixture only; never exposed to either executor role',
      writeCheck: 'Control-only test oracle uses separate nonowner role; visitor INSERT and sandbox reassignment stay denied',
      catalogVisibility: 'Private control relations are denied; ordinary PostgreSQL system metadata is not claimed hidden' } };
}
