// Worker for the two-worker routing/fencing proof (serve-only). Each worker
// process runs:
//   * a bounded HTTP server on the internal docker network (public + internal
//     + control surfaces, routed by the owner-aware router);
//   * per-session SDK runtimes backed by the real 887 SQLite runtime, whose
//     query adapter is the fenced executor (catalog owner + generation);
//   * a control action handler (drain / retire / dump) driven by the
//     proof host over the control HMAC.
// The router strips X-Proof-* headers on the public surface, enforces the
// public trust boundary (Origin allowlist + expected Host), validates the
// internal hop (HMAC + hop limit + deadline + catalog re-resolve), and
// re-resolves owner/generation so a forged or stale header cannot win.
// The host driver runs the scenarios and signals shutdown. Exactly one
// WORKER_ROUTING_FENCING_PROOF result record is emitted on shutdown.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import http from 'node:http';
import pg from 'pg';
import { createRuntimeManager, runtimeDescription } from '../sqlite-runtime-proof/runtime.mjs';
import { createExecutors } from './executor.mjs';
import { createCatalog } from './catalog.mjs';
import { createRouter, PROOF_HEADERS } from './router.mjs';

const PREFIX = 'WORKER_ROUTING_FENCING_PROOF ';
const emit = (record) => process.stdout.write(`${PREFIX}${JSON.stringify(record)}\n`);
const trace = [];
const checks = [];
const events = [];
// F6: one runtime per SESSION TOKEN (not per sandbox). A session's SDK
// identity is bound to (token, holding worker); routing never mints a second
// identity for a token, and a fresh token on the same sandbox gets a fresh
// runtime (the old one is evicted when its token stops resolving).
const sessions = new Map(); // token -> { token, sandbox, manager, runtime, master, holder, did }
const discards = [];         // { token, reason } — every runtime evicted mid-flight
const workerId = process.env.WORKER_ID;
let stage = 'configuration';

function env(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Missing ${name}`);
  return value;
}

function connectionString(name) {
  const url = new URL(env(name));
  if (!['postgres:', 'postgresql:'].includes(url.protocol) || !url.username) {
    throw new Error(`Invalid ${name}`);
  }
  return env(name);
}

const report = { protocol: 1, status: 'FAIL', worker: workerId, checks, events, trace, runtime: {} };
let pools = {};
let catalog;
let executors;
let router;
let server;
const masterKey = Buffer.from(process.env.ROUTING_MASTER_KEY ?? '', 'hex');

// Each session runtime shares one query adapter that passes the holder's
// current belief (owner + generation) into every fenced transaction. The
// belief itself is fixed in memory -- see tokenOwners below -- and is only
// updated by revalidate: the authority is the transaction fence, not the
// adapter.
function adapterFor(sandbox, holder) {
  return { query: (sql, params) => executors.withSandbox('query', sandbox,
    (client) => client.query(sql, params), holder.current) };
}

// The worker's *belief* of who owns a session, established once when it first
// serves the token and kept in memory afterwards. This is deliberately NOT
// re-read from the catalog on every operation: the authority is the fenced
// transaction. If the catalog's generation was bumped (or the session lost)
// while this worker was paused, its cached owner+generation is stale and the
// verify_fence inside the executor raises, the mutation rolls back, and the
// worker reports 409. That is exactly the "resumed worker with a stale
// generation is rejected" contract -- self-healing from the catalog would
// defeat it.
const tokenOwners = new Map(); // token -> { sandbox, owner, generation }

async function ownershipFor(token) {
  const cached = tokenOwners.get(token);
  if (cached) return cached;
  const session = await catalog.resolve(token);
  if (!session) return null; // lost / deleted -> 410
  const established = { sandbox: session.sandboxId, owner: session.owner,
    generation: Number(session.generation) };
  tokenOwners.set(token, established);
  return established;
}

// Materialize the session's SDK runtime (one per token, first-wins). Persists
// the agent DID to the catalog so any later worker can detect that this token
// already carries an identity it does not hold (F7 incompatible-runtime).
async function materialize(token, ownership) {
  const existing = sessions.get(token);
  if (existing) return existing;
  const holder = { current: { owner: ownership.owner, generation: ownership.generation } };
  const adapter = adapterFor(ownership.sandbox, holder);
  const manager = createRuntimeManager(adapter, connectionString('ROUTING_QUERY_URL'));
  // Buffer.from copies (slice/subarray would alias the module key, so an
  // evicted record's zero-fill would corrupt the master for later sessions).
  const master = Buffer.from(masterKey);
  const runtime = await manager.create(master, `s-${ownership.sandbox.slice(0, 4)}`);
  await runtime.populate();
  const record = { token, sandbox: ownership.sandbox, manager, runtime, master, holder,
    did: runtime.agent?.did ?? null };
  sessions.set(token, record);
  try {
    if (record.did) await catalog.setRuntimeDid(token, record.did);
  } catch (error) {
    // Catalog unreachable: the session still works (the fence re-asserts on
    // recovery), but the identity is not yet durably recorded.
    events.push({ type: 'set-runtime-did-failed', token, code: error?.code ?? null });
  }
  return record;
}

// Evict a session's runtime after an observed loss or transfer away from this
// worker. The manager is closed and the master key material is zeroed; the
// discard is recorded so the driver can dump the evidence.
async function evict(token, reason) {
  const record = sessions.get(token);
  tokenOwners.delete(token);
  if (!record) return;
  sessions.delete(token);
  discards.push({ token, reason });
  try {
    await record.manager.closeAll();
    assert.equal(record.manager.summary().live, 0);
  } catch { /* the worker's shutdown cleanup still accounts for stores */ }
  record.master.fill(0);
}

async function ensureRuntime(token, ownership) {
  const existing = sessions.get(token);
  if (existing) return existing;
  // F7: if the catalog already recorded a runtime identity for this token and
  // this worker does not hold it, serving would require minting (or adopting
  // a foreign) DID. Never do that: the session is incompatible here.
  const session = await catalog.resolve(token);
  if (!session) return null;
  if (session.runtimeDid) {
    return { status: 410, body: { error: 'session-lost', detail: 'incompatible-runtime' } };
  }
  return materialize(token, ownership);
}

async function localExecute(token, operation, params = {}, body) {
  const ownership = await ownershipFor(token);
  if (!ownership) {
    tokenOwners.delete(token);
    return { status: 410, body: { error: 'session-lost', detail: 'start-a-new-session' } };
  }
  const owner = ownership.owner, generation = ownership.generation;
  const sandbox = ownership.sandbox;
  let record = await ensureRuntime(token, ownership);
  if (!record) return { status: 410, body: { error: 'session-lost', detail: 'start-a-new-session' } };
  if (record && 'status' in record && record.body) return record;
  const { holder, runtime } = record;
  holder.current = { owner, generation };
  const adapterOwnership = { owner, generation };
  // Predefined fenced mutation: the SQL is chosen server-side (visitor SQL is
  // not arbitrary), but it runs through the same verify_fence + context + RLS
  // boundary as every other mutation.
  const MUTATE = 'UPDATE public.orders_plaintext SET quantity = quantity + 1 WHERE id = 1';
  try {
    switch (operation) {
      case 'renew': {
        // Extend this session's lease. Only succeeds while this worker still
        // holds owner + generation; a bumped or transferred session refuses.
        const renewed = await catalog.renewLease(owner, token, generation,
          Number(process.env.ROUTING_LEASE_MS ?? 30000));
        return { status: renewed ? 200 : 409,
          body: { renewed, owner, generation } };
      }
      case 'query': {
        const result = await runtime.query();
        return { status: 200, body: { rows: result.rows, owner, generation } };
      }
      case 'rawsql': {
        const result = await executors.raw(sandbox, 'SELECT count(*)::int AS n FROM public.orders_plaintext', [], adapterOwnership);
        return { status: 200, body: { rows: result.rows, owner, generation } };
      }
      case 'mutate': {
        // Writes run under the raw role (888 model: proof_query is read-only,
        // proof_raw holds the DML grants). The fenced transaction boundary and
        // RLS policy are identical regardless of role.
        const result = await executors.withSandbox('raw', sandbox,
          (client) => client.query(MUTATE), adapterOwnership);
        return { status: 200, body: { owner, generation, committed: result.command } };
      }
      case 'hold': {
        // In-flight mutation: takes the per-sandbox advisory lock (via
        // verify_fence) and holds it for ~2s, so the janitor and any
        // generation bump observe a live in-flight mutation and defer.
        const result = await executors.withSandbox('raw', sandbox,
          (client) => client.query('SELECT pg_sleep(2) AS held'), adapterOwnership);
        return { status: 200, body: { owner, generation, held: result.rows[0]?.held ?? 2 } };
      }
      case 'rawbytes': {
        const result = await executors.rawBytes(sandbox, adapterOwnership);
        return { status: 200, body: { ...result, owner, generation } };
      }
      case 'reset': {
        // Fenced reset: the sandbox's private rows are deleted and reseeded
        // inside the ownership transaction, so a stale worker cannot reset
        // over a live owner's data.
        await executors.reset(sandbox, adapterOwnership);
        const result = await runtime.query();
        return { status: 200, body: { rows: result.rows, owner, generation } };
      }
      case 'agents': {
        const agents = await runtime.scope.listAgents();
        return { status: 200, body: { agents, owner, generation } };
      }
      case 'present': {
        const { presentation } = await runtime.scope.createPresentationForAgent({
          agentDid: runtime.agent.did, credential: runtime.credential,
          requesterDid: runtime.owner.did });
        return { status: 200, body: { presentation, agentDid: runtime.agent.did, owner, generation } };
      }
      case 'delegate': {
        const target = await runtime.scope.createAgentIdentity({
          name: `Proof delegate ${runtime.label}`, ownerDid: runtime.owner.did });
        const delegated = await runtime.scope.delegateCredential(runtime.agent.did, runtime.credential, {
          targetAgent: target.did, columns: ['orders.id'], actions: ['read'], expiresIn: '5m' });
        return { status: 200, body: {
          targetDid: target.did, delegated: typeof delegated === 'string' && delegated.length > 0,
          owner, generation } };
      }
      case 'audit': {
        const chain = await runtime.scope.auditLoggerInstance.verifyAuditChain();
        return { status: 200, body: { chainOk: chain?.ok === true,
          totalRecords: chain?.totalRecords ?? null, owner, generation } };
      }
      case 'ping': {
        // Body transport probe: echoes the request body end-to-end (public ->
        // router -> forward -> internal -> worker) to prove the JSON body
        // survives the hop chain.
        return { status: 200, body: { echo: body ?? null, owner, generation } };
      }
      case 'status': {
        // Report the worker's in-memory belief (owner + generation it fenced
        // with) plus the SDK identity for this session. The DID is stable
        // for the lifetime of the session token (one runtime per token),
        // which is what "no new identity is created" means.
        return { status: 200, body: { owner, generation, sandbox,
          runtimeDid: runtime.agent?.did ?? null } };
      }
      case 'revalidate': {
        // Re-check the catalog for this token. If it was lost, the worker
        // evicts its runtime (F6) and reports 410. If it is still live and
        // owned by THIS worker, it may adopt the newer generation (e.g. after
        // a self lease-renewal). If another worker now owns it, the runtime
        // for this token is terminal here: evict it so the stale belief can
        // never be served again.
        const fresh = await catalog.resolve(token);
        if (!fresh) {
          await evict(token, 'revalidate-lost');
          return { status: 410, body: { error: 'session-lost', detail: 'start-a-new-session' } };
        }
        if (fresh.owner === workerId) {
          tokenOwners.set(token, { sandbox: fresh.sandboxId, owner: fresh.owner,
            generation: Number(fresh.generation) });
        } else {
          await evict(token, 'revalidate-transferred-away');
        }
        return { status: 200, body: { owner: fresh.owner, generation: Number(fresh.generation),
          sandbox: fresh.sandboxId, self: fresh.owner === workerId } };
      }
      default:
        return { status: 400, body: { error: 'unknown-operation', operation } };
    }
  } catch (error) {
    // F2: the fence reason is authoritative for the client's next move.
    // Stale ownership / lock contention are 409 (retryable conditions).
    // An expired lease rejects the mutation with a defined 410 but does NOT
    // evict the runtime: the same worker can renew the same session and
    // continue serving it. The remaining terminal reasons (session-lost,
    // owner-retired, drain-deadline) evict the local runtime (F6).
    if (error?.code === 'FENCE_REJECTED') {
      const reason = error.reason ?? 'unknown';
      if (reason === 'lease-expired') {
        return { status: 410, body: { error: 'session-lost', detail: 'lease-expired' } };
      }
      const terminal = ['session-lost', 'owner-retired', 'drain-deadline'];
      if (terminal.includes(reason)) {
        await evict(token, `fence-${reason}`);
        return { status: 410, body: { error: 'session-lost', detail: reason } };
      }
      return { status: 409, body: { error: 'stale-ownership', reason, owner, generation } };
    }
    // Catalog/PG unreachable (dependency down) -> 503, distinct from a fence.
    // 53300 = too_many_connections, 57P01 = admin_shutdown, plus the
    // system-level codes node-postgres surfaces when the socket is gone.
    if (error?.code === '53300' || error?.code === '57P01'
      || error?.code === 'ECONNREFUSED' || error?.code === 'ECONNRESET' || error?.code === 'ETIMEDOUT'
      || /could not connect|connection (was|has been) terminated|socket hang up|query timeout|pool acquire timeout/i.test(error?.message ?? '')) {
      return { status: 503, body: { error: 'dependency-unavailable', owner, generation } };
    }
    return { status: 400, body: { error: error?.code ?? 'operation-failed', owner, generation } };
  }
}

async function controlAction(action) {
  if (action === 'drain') {
    const graceMs = Number(env('ROUTING_DRAIN_GRACE_MS') ?? 20000);
    await catalog.drainWorker(workerId, graceMs);
    return { ok: true, action, graceMs };
  }
  if (action === 'retire') {
    await catalog.retireWorker(workerId);
    return { ok: true, action };
  }
  if (action === 'dump') {
    return { ok: true, action, worker: workerId, status: report.status,
      events, trace, liveTokens: [...sessions.keys()], discards };
  }
  throw new Error(`Unknown control action: ${action}`);
}

const MAX_BODY_BYTES = 100 * 1024; // mirrors the playground server's JSON limit

function startServer(port) {
  server = http.createServer((req, res) => {
    const headers = {};
    for (const [key, value] of Object.entries(req.headers)) headers[key.toLowerCase()] = value;
    const url = req.url ?? '/';
    const [pathname, queryString = ''] = url.split('?');
    const searchParams = new URLSearchParams(queryString);
    (async () => {
      let body;
      if (req.method === 'POST' || req.method === 'PUT') {
        const chunks = [];
        let size = 0;
        for await (const chunk of req) {
          size += chunk.length;
          if (size > MAX_BODY_BYTES) {
            res.writeHead(413, { 'content-type': 'application/json' });
            res.end(JSON.stringify({ error: 'payload-too-large' }));
            return;
          }
          chunks.push(chunk);
        }
        if (size > 0) {
          try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); }
          catch {
            res.writeHead(400, { 'content-type': 'application/json' });
            res.end(JSON.stringify({ error: 'invalid-json-body' }));
            return;
          }
        }
      }
      let result;
      if (pathname === '/control') {
        result = await router.handleControl(headers);
      } else if (pathname.startsWith('/internal/')) {
        result = await router.handleInternal(url, headers, body);
      } else {
        const stripped = { ...headers };
        for (const name of PROOF_HEADERS) delete stripped[name];
        result = await router.handlePublic(pathname, searchParams, stripped, req.method, body);
      }
      res.writeHead(result.status, { 'content-type': 'application/json' });
      res.end(JSON.stringify(result.body ?? {}));
    })().catch((error) => {
      res.writeHead(500, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: error?.message ?? 'internal' }));
    });
  });
  return new Promise((resolve) => server.listen(port, '0.0.0.0', resolve));
}

// The janitor is driven directly by the proof host (driver calls
// proof_ctrl.janitor_sweep over its own control connection) so the driver is
// the single, deterministic source of janitor behavior in this proof.

const ownerEndpoints = {
  'worker-a': `http://worker-a:${env('WORKER_PORT') ?? 8080}`,
  'worker-b': `http://worker-b:${env('WORKER_PORT') ?? 8080}`,
};

const port = Number(process.env.WORKER_PORT ?? 8080);
const allowedOrigins = (process.env.ROUTING_ALLOWED_ORIGINS ?? '')
  .split(',').map((value) => value.trim()).filter(Boolean);

try {
  assert.equal(process.versions.node.split('.')[0], '22', 'Use the actual Node 22 runtime image');
  assert.ok(masterKey.length === 32, 'Master key must be 32 bytes');
  report.runtime = runtimeDescription();
  report.runtimeModuleSha256 = createHash('sha256').update(await readFile(new URL('../sqlite-runtime-proof/runtime.mjs', import.meta.url))).digest('hex');

  stage = 'pools';
  // Idle pg clients emit 'error' on disconnect (ECONNRESET) and when the
  // server terminates them (57P01) during the catalog-down fault. Those are
  // EXPECTED and must not crash the worker or be reported as a pool defect.
  const onPoolError = (error) => {
    if (error?.code === '57P01' || error?.code === 'ECONNRESET'
      || /terminating connection|connection (was|has been) terminated|socket hang up/i.test(error?.message ?? '')) {
      return; // expected during the intentional postgres stop
    }
    report.poolError = error?.message ?? String(error);
  };
  const poolOptions = { connectionTimeoutMillis: 3000, statement_timeout: 5000 };
  pools = {
    query: new pg.Pool({ ...poolOptions, connectionString: connectionString('ROUTING_QUERY_URL'),
      max: 3, application_name: `${workerId}-query` }),
    raw: new pg.Pool({ ...poolOptions, connectionString: connectionString('ROUTING_RAW_URL'),
      max: 2, application_name: `${workerId}-raw` }),
    control: new pg.Pool({ ...poolOptions, connectionString: connectionString('ROUTING_CONTROL_URL'),
      max: 2, application_name: `${workerId}-control` }),
  };
  for (const pool of Object.values(pools)) pool.on('error', onPoolError);

  catalog = createCatalog({ adminUrl: connectionString('ROUTING_ADMIN_URL'), onPoolError });

  stage = 'executors';
  executors = createExecutors({ queryPool: pools.query, rawPool: pools.raw,
    controlPool: pools.control, events, worker: workerId });

  const routingSecrets = {
    'worker-a': env('ROUTING_SECRET_A'),
    'worker-b': env('ROUTING_SECRET_B'),
  };
  router = createRouter({
    workerId, routingSecrets, controlSecret: env('ROUTING_CONTROL_SECRET'), catalog,
    localExecute: (tokenHashValue, operation, body) => localExecute(tokenHashValue, operation, {}, body),
    reserve: (tokenHashValue, sandboxId) => catalog.reserve(tokenHashValue, sandboxId, workerId, Number(env('ROUTING_LEASE_MS') ?? 30000)),
    establishBelief: (token, ownership) => { tokenOwners.set(token, { sandbox: ownership.sandboxId, owner: ownership.owner, generation: ownership.generation }); },
    onSessionEstablished: async (token) => {
      const ownership = tokenOwners.get(token);
      if (!ownership) return null;
      const record = await materialize(token, ownership);
      return record.did;
    },
    workerState: async () => catalog.workerState(workerId),
    controlAction,
    ownerEndpoint: (worker) => ownerEndpoints[worker],
    trace: (entry) => trace.push(entry),
    evictSession: async (token) => { await evict(token, 'catalog-resolve-lost'); },
    expectedHost: `${workerId}:${port}`,
    allowedOrigins,
  });

  stage = 'server';
  await startServer(port);
  checks.push({ name: 'worker-ready', status: 'PASS' });
  report.status = 'PASS';
  emit({ type: 'ready', worker: workerId, port });
  await new Promise((resolve) => {
    process.once('SIGTERM', resolve);
    process.once('SIGINT', resolve);
  });
} catch (error) {
  report.failure = { stage, name: error?.name ?? 'Error',
    code: /^[A-Z0-9_]{3,40}$/.test(error?.code ?? '') ? error.code : 'CHECK_FAILED',
    source: /(?:worker|router|executor|catalog)\.mjs:\d+/.exec(error?.stack ?? '')?.[0],
    message: error?.message };
} finally {
  const cleanup = [];
  try {
    if (server) await new Promise((resolve) => server.close(resolve));
    cleanup.push({ resource: 'http-server', status: 'PASS' });
  } catch { cleanup.push({ resource: 'http-server', status: 'FAIL' }); }
  for (const [token, record] of [...sessions.entries()]) {
    try {
      await record.manager.closeAll();
      const summary = record.manager.summary();
      assert.equal(summary.live, 0);
      assert.equal(summary.storesCreated, summary.storesClosed);
      sessions.delete(token);
      record.master.fill(0);
      cleanup.push({ resource: `session-${token.slice(0, 8)}`, status: 'PASS', summary });
    } catch { cleanup.push({ resource: `session-${token.slice(0, 8)}`, status: 'FAIL' }); }
  }
  for (const [name, pool] of Object.entries(pools)) {
    try {
      await pool.end();
      cleanup.push({ resource: `pool-${name}`, status: pool.totalCount === 0 ? 'PASS' : 'FAIL' });
    } catch { cleanup.push({ resource: `pool-${name}`, status: 'FAIL' }); }
  }
  try { if (catalog) await catalog.close(); } catch { /* already closed via pool */ }
  masterKey.fill(0);
  report.cleanup = { status: cleanup.every((item) => item.status === 'PASS') ? 'PASS' : 'FAIL', resources: cleanup };
  if (report.poolError || report.cleanup.status !== 'PASS') report.status = 'FAIL';
  emit({ type: 'result', ...report });
}
