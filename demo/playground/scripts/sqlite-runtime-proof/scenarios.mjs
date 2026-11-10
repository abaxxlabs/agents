import { createHash } from 'node:crypto';
import { decodeJwt, hashAuditRecord, verifyJwtSignature } from '@abaxxlabs/agents';
import { BASE_SQL, BROAD_SQL, check, snapshot } from './runtime.mjs';

const EXPECTED = [
  { id: 1, instrument: 'LNG', quantity: 10, price: 12.45, counterparty: 'Example A' },
  { id: 2, instrument: 'CARBON', quantity: 20, price: 88.1, counterparty: 'Example B' },
];
const SIGNED_FIELDS = ['id', 'timestamp', 'agentDid', 'ownerDid', 'credentialId', 'queryHash',
  'columnsAccessed', 'rowCount', 'durationMs', 'orgId', 'delegatorDid', 'delegatedGrantId'];

function rowsMatch(rows, broad = false) {
  const keys = ['id', 'instrument', 'quantity', 'price', ...(broad ? ['counterparty'] : [])];
  return rows.length === 2 && rows.every((row, index) =>
    Object.keys(row).length === keys.length && keys.every((key) => key === 'price'
      ? Number(row[key]) === EXPECTED[index][key] : row[key] === EXPECTED[index][key]));
}

function queryMatches(result, broad = false) {
  return rowsMatch(result.rows, broad) && result.metadata.rowCount === 2
    && result.metadata.columnsDecrypted.includes('orders.price')
    && (!broad || result.metadata.columnsDecrypted.includes('orders.counterparty'));
}

async function rejection(operation, code) {
  try { await operation(); return false; }
  catch (error) {
    if (error?.code !== code) throw error;
    return true;
  }
}

async function unavailable(operation) {
  try { await operation(); return false; } catch { return true; }
}

function assertPools(context, name, expectedLive = 0) {
  const summary = context.manager.summary();
  check(context.checks, name,
    summary.live === expectedLive && summary.inFlight === 0
    && context.queryPool.waitingCount === 0 && context.rawPool.waitingCount === 0
    && context.queryPool.totalCount <= 2 && context.rawPool.totalCount <= 1,
    { live: summary.live, inFlight: summary.inFlight });
}

async function recordSample(context, phase, cycle = 0) {
  const sample = await snapshot(context, phase, cycle);
  context.metrics.samples.push(sample);
  context.emit({ type: 'sample', ...sample });
  return sample;
}

async function roleState(pool) {
  const identity = await pool.query(`SELECT current_user AS role, current_database() AS database,
    current_setting('application_name') AS application_name,
    current_setting('statement_timeout') AS statement_timeout,
    rolsuper, rolbypassrls, rolcreatedb, rolcreaterole
    FROM pg_roles WHERE rolname = current_user`);
  const privileges = await pool.query(`SELECT c.relname,
    has_table_privilege(c.oid, 'SELECT') AS can_read,
    has_table_privilege(c.oid, 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') AS can_write
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm', 'f')`);
  return { identity: identity.rows[0], privileges: privileges.rows };
}

export async function checkFixture(context) {
  const query = await roleState(context.queryPool);
  const raw = await roleState(context.rawPool);
  const ordinary = (state) => state.identity && !state.identity.rolsuper && !state.identity.rolbypassrls
    && !state.identity.rolcreatedb && !state.identity.rolcreaterole;
  check(context.checks, 'separate-unprivileged-process-pools', ordinary(query) && ordinary(raw)
    && query.identity.role !== raw.identity.role && query.identity.database === raw.identity.database
    && query.identity.application_name === 'sqlite-runtime-proof-query'
    && raw.identity.application_name === 'sqlite-runtime-proof-raw'
    && query.identity.statement_timeout === '5s' && raw.identity.statement_timeout === '5s');
  const exactReads = (state, allowed) => state.privileges.every((row) =>
    row.can_read === allowed.includes(row.relname) && row.can_write === false)
    && allowed.every((name) => state.privileges.some((row) => row.relname === name && row.can_read));
  check(context.checks, 'postgres-query-role-read-only-data-and-key-metadata',
    exactReads(query, ['orders', 'agent_keys', 'agent_columns']), { discoveredRelations: query.privileges.length });
  check(context.checks, 'postgres-raw-role-plaintext-only', exactReads(raw, ['orders_plaintext']));
  check(context.checks, 'postgres-query-role-cannot-read-plaintext-control',
    await rejection(() => context.queryPool.query('SELECT * FROM public.orders_plaintext LIMIT 0'), '42501'));
  for (const table of ['agents', 'agent_audit', 'revoked_credentials', 'sessions', 'agent_context']) {
    check(context.checks, `postgres-query-role-cannot-read-${table}`,
      await rejection(() => context.queryPool.query(`SELECT * FROM public.${table} LIMIT 0`), '42501'));
  }
  const plaintext = await context.rawPool.query('SELECT id, instrument, quantity, price, counterparty FROM public.orders_plaintext ORDER BY id');
  check(context.checks, 'raw-plaintext-control-matches-fixture', rowsMatch(plaintext.rows, true), { rows: plaintext.rowCount });
  const ciphertext = await context.queryPool.query('SELECT id, instrument, quantity, price, counterparty FROM public.orders ORDER BY id');
  check(context.checks, 'postgres-protected-columns-are-ciphertext', ciphertext.rows.length === 2
    && ciphertext.rows.every((row, index) => row.id === EXPECTED[index].id
      && row.instrument === EXPECTED[index].instrument && row.quantity === EXPECTED[index].quantity
      && Buffer.isBuffer(row.price) && row.price.length > 30
      && Buffer.isBuffer(row.counterparty) && row.counterparty.length > 30), { rows: ciphertext.rowCount });
  const metadata = await context.queryPool.query(`SELECT table_name, column_name, is_encrypted
    FROM public.agent_columns WHERE table_name = 'orders' ORDER BY column_name`);
  check(context.checks, 'protected-column-metadata-loaded', ['price', 'counterparty'].every((column) =>
    metadata.rows.some((row) => row.column_name === column && row.is_encrypted === true)));
}

function signedFieldsMatch(record) {
  const payload = decodeJwt(record.signature).payload;
  return payload.aud === 'agents-audit' && payload.data
    && SIGNED_FIELDS.every((field) => JSON.stringify(payload.data[field]) === JSON.stringify(record[field]));
}

async function auditEvidence(runtime, checks, label) {
  const logger = runtime.scope.auditLoggerInstance;
  const records = await logger.export();
  const chain = await logger.verifyAuditChain();
  check(checks, `${label}-full-audit-chain`, chain.ok && !chain.partial
    && chain.totalRecords === records.length && records.length > 1, { records: records.length, partial: chain.partial });
  let signed = true;
  for (const record of records) {
    signed &&= await logger.verifyRecord(record, runtime.agent.publicKey) && signedFieldsMatch(record);
  }
  check(checks, `${label}-audit-signatures-and-covered-fields`, signed, { records: records.length });
  const first = records[0];
  const parts = first.signature.split('.');
  const signature = Buffer.from(parts[2], 'base64url');
  signature[0] ^= 1;
  parts[2] = signature.toString('base64url');
  check(checks, `${label}-corrupt-signature-rejected`,
    !(await logger.verifyRecord({ ...first, signature: parts.join('.') }, runtime.agent.publicKey)));
  const changed = { ...first, rowCount: first.rowCount + 1 };
  check(checks, `${label}-record-payload-mismatch-detected`, !signedFieldsMatch(changed)
    && !(await logger.verifyRecord(changed, runtime.agent.publicKey)));
  check(checks, `${label}-chain-link-tamper-detected`, records[1].previousHash === hashAuditRecord(first)
    && records[1].previousHash !== hashAuditRecord(changed));
  check(checks, `${label}-success-and-rejection-persisted`, records.some((record) => record.status === 'success')
    && records.some((record) => record.status === 'rejected'));
  return records;
}

async function createPair(context) {
  const a = await context.manager.create(context.masterKey, 'A');
  const b = await context.manager.create(context.masterKey, 'B');
  check(context.checks, 'independent-initial-empty-sqlite-stores', [a, b].every((runtime) =>
    Object.values(runtime.initialCounts).every((count) => count === 0)) && a.storage !== b.storage);
  check(context.checks, 'injected-resources-caller-owned', a.callerOwned && b.callerOwned);
  check(context.checks, 'independent-equal-key-buffers', a.masterKey !== b.masterKey && a.masterKey.equals(b.masterKey)
    && a.macKey !== b.macKey && a.macKey.equals(b.macKey));
  await a.populate();
  await b.populate();
  return { a, b };
}

async function exercisePair(context) {
  const { checks } = context;
  const { a, b } = await createPair(context);
  const firstA = await a.query();
  const presentForB = (credential) => b.scope.createPresentationForAgent({ agentDid: b.agent.did,
    credential, requesterDid: b.owner.did, audience: b.scope.verifierDid });
  const ownPresentation = await presentForB(b.credential);
  const firstB = await b.query({ credential: ownPresentation.presentation, requirePresentation: true });
  check(checks, 'A-encrypted-price-allowed-and-decrypted', queryMatches(firstA));
  check(checks, 'B-encrypted-price-allowed-and-decrypted', queryMatches(firstB));
  check(checks, 'agent-registry-isolation', a.agent.did !== b.agent.did
    && await a.scope.getAgent(b.agent.did) === null && await b.scope.getAgent(a.agent.did) === null
    && (await a.counts()).agents === 1 && (await b.counts()).agents === 1);
  const wrongPresentation = await presentForB(a.credential);
  const wrongClaims = decodeJwt(wrongPresentation.presentation).payload;
  check(checks, 'wrong-visitor-credential-denied-with-fresh-B-presentation',
    typeof wrongClaims.jti === 'string' && wrongClaims.jti !== ownPresentation.jti
    && wrongClaims.iss === b.agent.did && wrongClaims.aud === b.scope.verifierDid
    && wrongClaims.vp.verifiableCredential[0] === a.credential
    && await verifyJwtSignature(wrongPresentation.presentation, b.agent.publicKey)
    && await rejection(() => b.query({ credential: wrongPresentation.presentation, requirePresentation: true }), 'CREDENTIAL_INVALID'));
  check(checks, 'narrow-credential-denies-counterparty-same-sql',
    await rejection(() => a.query({ sql: BROAD_SQL }), 'SCOPE_VIOLATION'));
  const broad = await a.query({ credential: a.broadCredential, sql: BROAD_SQL });
  check(checks, 'broad-credential-positive-control-same-sql', queryMatches(broad, true));
  check(checks, 'B-denial-is-independently-audited',
    await rejection(() => b.query({ sql: BROAD_SQL }), 'SCOPE_VIOLATION'));
  const credential = decodeJwt(a.broadCredential).payload;
  check(checks, 'real-credential-has-owner-signature-and-jti', typeof credential.jti === 'string'
    && credential.iss === a.owner.did && credential.sub === a.agent.did
    && (await a.scope.verifierInstance.verify(a.broadCredential)).valid);
  await a.scope.verifierInstance.revokeAsync(credential.jti, {
    reason: 'runtime-proof', credentialExp: new Date(credential.exp * 1000),
  });
  check(checks, 'revoked-query-rejected-with-fresh-presentation',
    await rejection(() => a.query({ credential: a.broadCredential, sql: BROAD_SQL }), 'CREDENTIAL_REVOKED'));
  check(checks, 'sqlite-revocation-isolation', (await a.counts()).revocations === 1
    && (await b.counts()).revocations === 0 && !(await b.scope.verifierInstance.isRevoked(credential.jti))
    && (await b.scope.verifierInstance.verify(a.broadCredential, { expectedSubject: a.agent.did })).valid);
  check(checks, 'B-query-survives-A-revocation', queryMatches(await b.query()));
  const auditA = await auditEvidence(a, checks, 'A');
  const auditB = await auditEvidence(b, checks, 'B');
  const idsA = new Set(auditA.map((record) => record.id));
  check(checks, 'audit-store-isolation', auditA.every((record) => record.agentDid === a.agent.did)
    && auditB.every((record) => record.agentDid === b.agent.did && !idsA.has(record.id))
    && !(await b.storage.audit.query({ id: firstA.metadata.auditId })).length);
  check(checks, 'public-DID-signatures-verifiable-by-B', (await b.scope.verify(auditA[0])).valid);
  const successRecord = auditA.find((record) => record.id === firstA.metadata.auditId);
  check(checks, 'successful-query-audit-binds-query-and-credential', !!successRecord
    && successRecord.queryHash === createHash('sha256').update(BASE_SQL).digest('hex')
    && successRecord.credentialId === createHash('sha256').update(a.credential).digest('hex').slice(0, 16));
  const retainedStorageA = a.storage;
  const retainedDidA = a.agent.did;
  const pending = a.query();
  const closing = a.close({ characterizeSdk: true });
  check(checks, 'runtime-close-blocks-new-admission', await rejection(() => a.query(), 'PROOF_RUNTIME_CLOSED'));
  check(checks, 'runtime-close-drains-accepted-query', queryMatches(await pending));
  const disposal = await closing;
  const closedAgentCountUnavailable = await unavailable(() => retainedStorageA.agents.count());
  const closedAgentGetUnavailable = await unavailable(() => retainedStorageA.agents.findByDid(retainedDidA));
  check(checks, 'A-state-unavailable-through-retained-storage-after-explicit-close',
    closedAgentCountUnavailable && closedAgentGetUnavailable,
    { countRejected: closedAgentCountUnavailable, getRejected: closedAgentGetUnavailable });
  check(checks, 'close-A-preserves-caller-resources-until-explicit-disposal', disposal.draining >= 1
    && disposal.storageAccessibleAfterSdkClose && disposal.poolAccessibleAfterSdkClose && disposal.callerOwned);
  check(checks, 'caller-owned-A-buffers-overwritten', disposal.callerOwnedBuffersZeroed);
  check(checks, 'SDK-stale-handle-behavior-characterized',
    ['succeeded', 'rejected'].includes(disposal.sdkQueryAfterClose) && typeof disposal.retainedSignerUsable === 'boolean',
    { sdkQueryAfterClose: disposal.sdkQueryAfterClose, retainedSignerUsable: disposal.retainedSignerUsable });
  check(checks, 'A-final-audit-includes-drained-and-stale-handle-operations',
    disposal.auditAfterSdkClose.chainOk && disposal.auditAfterSdkClose.partial === false
    && disposal.auditAfterSdkClose.signaturesValid && disposal.auditAfterSdkClose.totalRecords >= auditA.length + 1,
    disposal.auditAfterSdkClose);
  check(checks, 'B-operates-after-A-storage-disposal', queryMatches(await b.query())
    && b.masterKey.equals(context.masterKey) && (await b.counts()).agents === 1);
  assertPools(context, 'one-live-runtime-after-A-close', 1);
  check(checks, 'caller-owned-B-buffers-overwritten', (await b.close()).callerOwnedBuffersZeroed);
  assertPools(context, 'no-live-runtimes-after-pair');
  context.metrics.teardownCharacterization = disposal;
}

async function fixedCycle(context, label) {
  const runtime = await context.manager.create(context.masterKey, label);
  try {
    await runtime.populate();
    const allowed = await runtime.query();
    const denied = await rejection(() => runtime.query({ sql: BROAD_SQL }), 'SCOPE_VIOLATION');
    const broad = await runtime.query({ credential: runtime.broadCredential, sql: BROAD_SQL });
    const claims = decodeJwt(runtime.broadCredential).payload;
    await runtime.scope.verifierInstance.revokeAsync(claims.jti, { credentialExp: new Date(claims.exp * 1000) });
    const revoked = await rejection(() => runtime.query({ credential: runtime.broadCredential, sql: BROAD_SQL }), 'CREDENTIAL_REVOKED');
    const chain = await runtime.scope.auditLoggerInstance.verifyAuditChain();
    const records = await runtime.scope.auditLoggerInstance.export();
    let signatures = true;
    for (const record of records) signatures &&= signedFieldsMatch(record)
      && await runtime.scope.auditLoggerInstance.verifyRecord(record, runtime.agent.publicKey);
    const counts = await runtime.counts();
    if (!(queryMatches(allowed) && denied && queryMatches(broad, true) && revoked
      && chain.ok && !chain.partial && chain.totalRecords === 4 && signatures
      && counts.agents === 1 && counts.audit === 4 && counts.revocations === 1)) {
      throw new Error('Fixed workload failed');
    }
  } finally {
    await runtime.close();
  }
}

function memoryTrend(samples) {
  const series = samples.filter((sample) => sample.phase === 'after-warmup' || sample.phase === 'measured');
  const first = series[0];
  const last = series.at(-1);
  const slopes = {};
  for (const key of Object.keys(first.memoryUsage)) {
    const meanX = series.reduce((sum, sample) => sum + sample.cycle, 0) / series.length;
    const meanY = series.reduce((sum, sample) => sum + sample.memoryUsage[key], 0) / series.length;
    const denominator = series.reduce((sum, sample) => sum + (sample.cycle - meanX) ** 2, 0);
    slopes[key] = { deltaBytes: last.memoryUsage[key] - first.memoryUsage[key],
      slopeBytesPerCycle: denominator === 0 ? null : series.reduce((sum, sample) =>
        sum + (sample.cycle - meanX) * (sample.memoryUsage[key] - meanY), 0) / denominator };
  }
  return { interpretation: 'observational; no universal pass/fail memory threshold', samples: series.length, values: slopes };
}

export async function runScenarios(context) {
  await checkFixture(context);
  await exercisePair(context);
  await recordSample(context, 'before-warmup');
  for (let cycle = 1; cycle <= context.warmup; cycle++) await fixedCycle(context, 'warmup');
  assertPools(context, 'warmup-resource-invariants');
  await recordSample(context, 'after-warmup');
  let cycle = 0;
  try {
    for (cycle = 1; cycle <= context.cycles; cycle++) {
      await fixedCycle(context, 'measured');
      const summary = context.manager.summary();
      if (summary.live !== 0 || summary.inFlight !== 0 || context.queryPool.waitingCount !== 0
        || context.rawPool.waitingCount !== 0 || context.queryPool.totalCount > 2 || context.rawPool.totalCount > 1) {
        throw new Error('Cycle resource invariant failed');
      }
      if (cycle % 25 === 0 || cycle === context.cycles) await recordSample(context, 'measured', cycle);
    }
  } catch (error) {
    context.checks.push({ name: 'fixed-workload-measured-cycles', status: 'FAIL', cycle });
    throw error;
  }
  check(context.checks, 'fixed-workload-measured-cycles', true, { completed: context.cycles, warmup: context.warmup,
    workload: 'one real scope/store/owner/agent; two signed credentials; allow, deny, broad positive, revoke, fresh-VP reject; four audit signatures and full chain; explicit disposal' });
  assertPools(context, 'final-cycle-resource-invariants');
  context.metrics.memoryTrend = memoryTrend(context.metrics.samples);
}

export async function holdScenarios(context) {
  await checkFixture(context);
  const { a, b } = await createPair(context);
  check(context.checks, 'hold-two-real-agent-queries', queryMatches(await a.query()) && queryMatches(await b.query()));
  const claims = decodeJwt(a.broadCredential).payload;
  await a.scope.verifierInstance.revokeAsync(claims.jti, { credentialExp: new Date(claims.exp * 1000) });
  check(context.checks, 'hold-revocation-persisted-before-kill', (await a.counts()).revocations === 1);
  context.emit({ type: 'ready', protocolVersion: 1, agents: [a.agent.did, b.agent.did], counts: [await a.counts(), await b.counts()],
    checks: context.checks, metrics: await snapshot(context, 'holding'), runtime: context.runtime, pid: process.pid });
  await new Promise(() => { setInterval(() => {}, 60_000); });
}

export async function restartScenarios(context) {
  await checkFixture(context);
  check(context.checks, 'restart-previous-public-agent-identities-supplied', context.previousAgents.length >= 2);
  const a = await context.manager.create(context.masterKey, 'restart-A');
  const b = await context.manager.create(context.masterKey, 'restart-B');
  check(context.checks, 'restart-empty-agents-audit-and-revocations', [a, b].every((runtime) =>
    Object.values(runtime.initialCounts).every((count) => count === 0)), { counts: [a.initialCounts, b.initialCounts] });
  let absent = true;
  for (const runtime of [a, b]) {
    for (const did of context.previousAgents) absent &&= await runtime.scope.getAgent(did) === null;
  }
  check(context.checks, 'restart-old-agents-not-recovered', absent, { checked: context.previousAgents.length });
  await a.populate();
  await b.populate();
  check(context.checks, 'restart-fresh-agent-queries-same-postgres', queryMatches(await a.query()) && queryMatches(await b.query())
    && !context.previousAgents.includes(a.agent.did) && !context.previousAgents.includes(b.agent.did));
  await a.close();
  check(context.checks, 'restart-B-survives-A-close', queryMatches(await b.query()));
  await b.close();
  assertPools(context, 'restart-no-live-runtimes');
  await recordSample(context, 'restart-complete');
}
