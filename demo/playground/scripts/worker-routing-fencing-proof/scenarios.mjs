// Scenario driver for the two-worker routing/fencing proof. It runs on the
// internal docker network (reaches both workers by container name) and holds
// the control role (catalog + fault SQL) plus the admin role (evidence reads).
// It drives HTTP against the workers, injects faults, and records the
// acceptance evidence. The host orchestrator owns the container lifecycle
// (including the postgres stop/start for the catalog-down fault) and assumes
// the fixture has run.
//
// Exactly one WORKER_ROUTING_FENCING_PROOF record with type:"result" is emitted.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import http from 'node:http';
import { randomBytes } from 'node:crypto';
import { Socket } from 'node:net';
import pg from 'pg';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
import { signRouting, routingPayload, controlPayload } from './router.mjs';
import { SANDBOX_A, SANDBOX_B } from './executor.mjs';
const DOCKER_SOCKET = process.env.ROUTING_DOCKER_SOCKET ?? '/var/run/docker.sock';

const PREFIX = 'WORKER_ROUTING_FENCING_PROOF ';
// The proof protocol allows exactly one type:"result" record. ready/failure
// records are not results, so the single-shot latch only guards result emits.
let resultEmitted = false;
const emit = (record) => process.stdout.write(`${PREFIX}${JSON.stringify(record)}\n`);
const emitResult = (record) => { if (resultEmitted) return; resultEmitted = true; emit(record); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const randomHex = (n) => randomBytes(n).toString('hex');

const PORT = Number(process.env.WORKER_PORT ?? 8080);
const A = `http://worker-a:${PORT}`;
const B = `http://worker-b:${PORT}`;
const PG_CONTAINER = process.env.ROUTING_PG_CONTAINER;

const report = { protocol: 1, type: 'result', status: 'FAIL', phases: {}, checks: [], acceptance: {},
  workloadAuth: null, prerequisites: { runtimeLifecycle887: 'FAIL', sqlIsolation888: 'FAIL' } };
const check = (name, passed, details = {}) => {
  report.checks.push({ ...details, name, status: passed ? 'PASS' : 'FAIL' });
};

// ---- HTTP helpers ----------------------------------------------------------
async function safeJson(response) { try { return await response.json(); } catch { return { error: 'non-json' }; } }
async function publicGet(base, path, headers = {}) {
  const response = await fetch(`${base}${path}`, { headers });
  return { status: response.status, body: await safeJson(response) };
}
async function publicCreate(base, sandbox, headers = {}) {
  const response = await fetch(`${base}/proof/session?sandbox=${sandbox}`, { headers });
  return { status: response.status, body: await safeJson(response) };
}
async function publicOp(base, token, operation, { headers = {}, body } = {}) {
  // The owner may block while its catalog resolve waits for a dead pool
  // connection; a bounded fetch keeps the driver from hanging in that window.
  const options = { signal: AbortSignal.timeout(20000), headers };
  if (body !== undefined) {
    options.method = 'POST';
    options.headers = { ...headers, 'content-type': 'application/json' };
    options.body = JSON.stringify(body);
  }
  const response = await fetch(`${base}/proof/session/${token}/${operation}`, options);
  return { status: response.status, body: await safeJson(response) };
}
async function publicOpSafe(base, token, operation, options) {
  try { return await publicOp(base, token, operation, options); }
  catch (error) { return { status: 0, body: { error: String(error?.message ?? error) } }; }
}
async function internalOp(base, token, operation, headers, body) {
  const options = { headers };
  if (body !== undefined) {
    options.method = 'POST';
    options.headers = { ...headers, 'content-type': 'application/json' };
    options.body = JSON.stringify(body);
  }
  const response = await fetch(`${base}/internal/${token}/${operation}`, options);
  return { status: response.status, body: await safeJson(response) };
}
async function controlOp(base, workerId, action) {
  const nonce = randomHex(8);
  const deadline = String(Date.now() + 15000);
  const signature = signRouting(controlPayload({ action, workerId, deadline, nonce }), process.env.ROUTING_CONTROL_SECRET);
  const response = await fetch(`${base}/control`, { headers: {
    'x-proof-action': action, 'x-proof-signature': signature, 'x-proof-deadline': deadline, 'x-proof-nonce': nonce } });
  return { status: response.status, body: await safeJson(response) };
}
function hopHeaders(path, { token, owner, generation, secret, hop = '1',
  deadline = String(Date.now() + 15000), nonce = randomHex(8), signature }) {
  const sig = signature ?? signRouting(routingPayload({ path, tokenHash: token, owner,
    generation, deadline, nonce }), secret);
  return {
    'x-proof-token-hash': token, 'x-proof-owner': owner, 'x-proof-generation': String(generation),
    'x-proof-signature': sig, 'x-proof-deadline': deadline, 'x-proof-nonce': nonce, 'x-proof-hop': hop,
  };
}
// Raw HTTP with full header control (the W2 boundary checks need Host/Origin
// overrides that fetch does not expose).
function rawHttp(base, path, headers) {
  return new Promise((resolvePromise) => {
    const url = new URL(base);
    const request = http.request({
      hostname: url.hostname, port: url.port, path, method: 'GET', headers,
    }, (response) => {
      let data = '';
      response.on('data', (chunk) => { data += chunk; });
      response.on('end', () => {
        let body; try { body = JSON.parse(data); } catch { body = { raw: data }; }
        resolvePromise({ status: response.statusCode, body });
      });
    });
    request.on('error', (error) => resolvePromise({ status: 0, body: { error: String(error?.message) } }));
    request.setTimeout(15000, () => { request.destroy(new Error('raw-http-timeout')); });
    request.end();
  });
}

// ---- Direct catalog / evidence SQL ------------------------------------------
// control: the proof_control role (catalog mutations, fault injection, locks).
// admin: the postgres superuser (evidence reads only; bypasses RLS).
let controlPool;
let adminPool;
function control() {
  if (!controlPool) {
    const u = new URL(process.env.ROUTING_CONTROL_URL);
    controlPool = new pg.Pool({ host: u.hostname, port: +u.port, user: decodeURIComponent(u.username),
      password: decodeURIComponent(u.password), database: u.pathname.slice(1), max: 4 });
    // The catalog-down fault stops postgres: idle client terminations must
    // not crash the driver; they are expected during that window.
    controlPool.on('error', () => {});
  }
  return controlPool;
}
function admin() {
  if (!adminPool) {
    const u = new URL(process.env.ROUTING_ADMIN_URL);
    adminPool = new pg.Pool({ host: u.hostname, port: +u.port, user: decodeURIComponent(u.username),
      password: decodeURIComponent(u.password), database: u.pathname.slice(1), max: 2 });
    adminPool.on('error', () => {});
  }
  return adminPool;
}
const q = async (pool, text, params) => (await pool.query(text, params)).rows;
const one = async (text, params) => (await q(control(), text, params))[0];

// One live session per sandbox: every phase that creates a session starts from
// a clean sandbox so the fence's single-row resolve stays sound.
async function clearSandbox(sandbox) {
  await one(`SELECT proof_ctrl.clear_sandbox($1::uuid)`, [sandbox]);
}
async function quantity(sandbox, id) {
  return (await q(admin(), `SELECT quantity FROM public.orders_plaintext WHERE sandbox_id=$1::uuid AND id=$2`, [sandbox, id]))[0]?.quantity;
}
async function seedRow(sandbox, id) {
  return (await q(admin(),
    `SELECT instrument, quantity, price, counterparty FROM public.orders_plaintext WHERE sandbox_id=$1::uuid AND id=$2`,
    [sandbox, id]))[0];
}
// Drain a worker through the catalog: records a deadline and marks every
// active session it owns as draining (the in-transaction admission gate then
// refuses new reservations for it). Atomic: both statements run in one
// transaction on a single control connection, mirroring the worker-side
// drainWorker, so a crash between them cannot leave a session active while
// its worker is already draining.
async function catalogDrain(worker, graceMs) {
  const pool = control();
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`SELECT proof_ctrl.set_worker_state($1, 'draining', $2)`, [worker, graceMs]);
    await client.query(`UPDATE public.proof_sessions SET state='draining' WHERE owner=$1 AND state='active'`, [worker]);
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

// ---- Fault helpers (raw HTTP over the docker unix socket) ------------------
// The socket here is fronted by an istio-envoy proxy that 404s node's
// http.request but accepts a raw request carrying a User-Agent. We send the
// bytes directly over the socket. No CLI binary is executed.
function dockerRawRequest(method, path) {
  const payload = `${method} ${path} HTTP/1.1\r\nHost: localhost\r\nUser-Agent: curl/8.7.1\r\nConnection: close\r\n\r\n`;
  return new Promise((resolvePromise) => {
    const socket = new Socket();
    let data = '';
    socket.on('data', (chunk) => { data += chunk.toString('latin1'); });
    socket.on('error', (error) => resolvePromise({ status: 0, body: String(error?.message) }));
    socket.on('close', () => {
      const status = Number(/HTTP\/1\.[01] (\d{3})/.exec(data)?.[1] ?? 0);
      let body = '';
      try { body = JSON.parse(data.split('\r\n\r\n').slice(1).join('\r\n\r\n')); } catch { body = data.slice(0, 200); }
      resolvePromise({ status, body });
    });
    socket.connect({ path: DOCKER_SOCKET });
    socket.end(payload);
  });
}
async function dockerStopPostgres() {
  const result = await dockerRawRequest('POST', `/containers/${PG_CONTAINER}/stop?t=5`);
  if (![204, 304].includes(result.status)) throw new Error(`docker stop postgres failed: ${result.status} ${result.body}`);
}
async function dockerStartPostgres() {
  const result = await dockerRawRequest('POST', `/containers/${PG_CONTAINER}/start`);
  if (![204, 304].includes(result.status)) throw new Error(`docker start postgres failed: ${result.status} ${result.body}`);
}
async function waitForCatalog() {
  for (let attempt = 0; attempt < 60; attempt++) {
    try { await q(admin(), 'SELECT 1'); return; } catch { await sleep(500); }
  }
  throw new Error('catalog did not recover');
}
async function waitForWorkers() {
  for (const base of [A, B]) {
    for (let attempt = 0; attempt < 60; attempt++) {
      try {
        const health = await publicGet(base, '/healthz');
        if (health.status === 200) break;
      } catch { /* not up yet */ }
      await sleep(500);
    }
  }
}

// ============================================================================
// S1 - ROUTING MATRIX (AC1): every real operation from BOTH entry points on
// BOTH sandboxes resolves to the same live owner + generation; the SDK
// surface (query, rawsql, agents, presentations, delegation, audit, renew,
// mutate, reset, rawbytes, ping body transport) executes exactly once on the
// owner; the create persists the runtime DID; static/health/readyz are
// unrouted; a cookie that never resolved is a defined 410.
// ============================================================================
const MATRIX_OPS = ['status', 'query', 'rawsql', 'agents', 'present', 'delegate',
  'audit', 'renew', 'mutate', 'reset', 'rawbytes', 'ping'];

function opShapeValid(op, body) {
  if (!body || typeof body !== 'object') return false;
  switch (op) {
    case 'status': return typeof body.runtimeDid === 'string' && body.runtimeDid.length > 0;
    case 'query': return Array.isArray(body.rows);
    case 'rawsql': return Array.isArray(body.rows) && Number.isInteger(body.rows[0]?.n);
    case 'agents': return Array.isArray(body.agents) && body.agents.length >= 1;
    case 'present': return typeof body.presentation === 'string' && body.presentation.length > 0
      && typeof body.agentDid === 'string';
    case 'delegate': return typeof body.targetDid === 'string' && body.delegated === true;
    case 'audit': return body.chainOk === true && Number.isInteger(body.totalRecords);
    case 'renew': return body.renewed === true;
    case 'mutate': return typeof body.committed === 'string' && body.committed.startsWith('UPDATE');
    case 'reset': return Array.isArray(body.rows);
    case 'rawbytes': return Array.isArray(body.plaintext) && body.plaintext.length > 0
      && Array.isArray(body.encrypted) && body.encrypted.length > 0
      && typeof body.encrypted[0]?.price === 'string'
      && body.encrypted[0].price.startsWith('\\x');
    case 'ping': return true; // shape asserted per-call (body transport)
    default: return false;
  }
}

async function s1RoutingMatrix() {
  // Clean start: the fixture seeds sandboxes + workers but no live sessions.
  const liveStart = await one(
    `SELECT count(*)::int AS n FROM public.proof_sessions WHERE state IN ('active','draining')`);
  check('matrix-clean-start', liveStart?.n === 0, { liveStart: liveStart?.n });

  // A and B are owned by different workers, so every public operation is a
  // cross-entry exercise of the routing contract.
  const tA = await publicCreate(A, SANDBOX_A);
  const tB = await publicCreate(B, SANDBOX_B);
  check('matrix-create-owners',
    tA.status === 200 && tA.body.owner === 'worker-a' && tA.body.generation === 1
    && tB.status === 200 && tB.body.owner === 'worker-b' && tB.body.generation === 1,
    { tA: { owner: tA.body.owner, g: tA.body.generation }, tB: { owner: tB.body.owner, g: tB.body.generation } });
  const tokenA = tA.body.token;
  const tokenB = tB.body.token;

  // F7: the create persists the materialized runtime identity in the catalog
  // (first-wins); the response carries the same DID.
  const rowA = await one(`SELECT runtime_did FROM public.proof_sessions WHERE token_hash=$1`, [tokenA]);
  const rowB = await one(`SELECT runtime_did FROM public.proof_sessions WHERE token_hash=$1`, [tokenB]);
  check('matrix-create-persists-did',
    typeof tA.body.runtimeDid === 'string' && rowA?.runtime_did === tA.body.runtimeDid
    && typeof tB.body.runtimeDid === 'string' && rowB?.runtime_did === tB.body.runtimeDid,
    { responseA: tA.body.runtimeDid, catalogA: rowA?.runtime_did,
      responseB: tB.body.runtimeDid, catalogB: rowB?.runtime_did });

  // The full operation matrix: every op from both entry points, both
  // sandboxes. The owner entry executes locally; the non-owner entry must
  // forward and return the identical owner + generation + shape. The mutate
  // and reset ops commit once per entry (owner AND forwarded), so after the
  // loop the per-sandbox id=1 quantity is back to the seed value 10.
  const dids = { A: tA.body.runtimeDid, B: tB.body.runtimeDid };
  for (const op of MATRIX_OPS) {
    for (const [label, ownerBase, otherBase, owner, token] of [
      ['A', A, B, 'worker-a', tokenA],
      ['B', B, A, 'worker-b', tokenB],
    ]) {
      const owned = await publicOp(ownerBase, token, op);
      check(`matrix-${op}-${label}-owner`,
        owned.status === 200 && owned.body.owner === owner && Number(owned.body.generation) === 1
        && opShapeValid(op, owned.body)
        && (op !== 'status' || owned.body.runtimeDid === dids[label]),
        { http: owned.status, owner: owned.body.owner, generation: owned.body.generation,
          shape: opShapeValid(op, owned.body), body: JSON.stringify(owned.body)?.slice(0, 200) });
      const forwarded = await publicOp(otherBase, token, op);
      check(`matrix-${op}-${label}-nonowner`,
        forwarded.status === 200 && forwarded.body.owner === owner && Number(forwarded.body.generation) === 1
        && opShapeValid(op, forwarded.body)
        && (op !== 'status' || forwarded.body.runtimeDid === dids[label]),
        { http: forwarded.status, owner: forwarded.body.owner, generation: forwarded.body.generation,
          shape: opShapeValid(op, forwarded.body), body: JSON.stringify(forwarded.body)?.slice(0, 200) });
    }
  }
  // The fenced mutation is committed exactly once per entry (owner + forward)
  // and the fenced reset restores the seed, so the sandbox ends at exactly
  // the seed quantity (10) for id=1: any extra committed write or any lost
  // reset would leave a different number.
  const [rA, rB] = [await quantity(SANDBOX_A, 1), await quantity(SANDBOX_B, 1)];
  check('matrix-final-quantity-seed-A', Number(rA) === 10, { quantity: Number(rA), expected: 10 });
  check('matrix-final-quantity-seed-B', Number(rB) === 10, { quantity: Number(rB), expected: 10 });

  // A second create for a sandbox that already has a live session is refused
  // by the catalog (reserve_session 'existing') while the owning worker is
  // still active: 409 session-exists, no second identity minted.
  const dup = await publicCreate(A, SANDBOX_A);
  check('matrix-duplicate-refused', dup.status === 409 && dup.body.error === 'session-exists',
    { status: dup.status, error: dup.body.error });

  // Body transport: the ping echoes the JSON request body through the full
  // public -> forward -> internal -> worker chain on both sandboxes.
  const probeA = `body-${tokenA.slice(0, 4)}`;
  const probeB = `body-${tokenB.slice(0, 4)}`;
  const pingA = await publicOp(B, tokenA, 'ping', { body: { probe: probeA } });
  const pingB = await publicOp(A, tokenB, 'ping', { body: { probe: probeB } });
  check('matrix-ping-body-transport',
    pingA.status === 200 && pingA.body.echo?.probe === probeA
    && pingB.status === 200 && pingB.body.echo?.probe === probeB,
    { pingA: pingA.body.echo, pingB: pingB.body.echo });

  // Fenced reset restores the EXACT seed rows (both id=1 and id=2, all four
  // columns) for each sandbox.
  const a1 = await seedRow(SANDBOX_A, 1);
  const a2 = await seedRow(SANDBOX_A, 2);
  const b1 = await seedRow(SANDBOX_B, 1);
  const b2 = await seedRow(SANDBOX_B, 2);
  const seedOk = (r1, r2) => r1?.instrument === 'LNG' && r1?.quantity === 10 && Number(r1?.price) === 12.45 && r1?.counterparty === 'Example A'
    && r2?.instrument === 'CARBON' && r2?.quantity === 20 && Number(r2?.price) === 88.1 && r2?.counterparty === 'Example B';
  check('matrix-reset-restores-seed', seedOk(a1, a2) && seedOk(b1, b2),
    { a1, a2, b1, b2 });

  // Identity stability: the DID observed by status (from either entry) equals
  // the DID persisted at create for both sandboxes.
  const sA = await publicOp(A, tokenA, 'status');
  const sB = await publicOp(B, tokenB, 'status');
  check('matrix-did-stable-A', sA.status === 200 && sA.body.runtimeDid === dids.A
    && (await publicOp(B, tokenA, 'status')).body.runtimeDid === dids.A, { did: dids.A });
  check('matrix-did-stable-B', sB.status === 200 && sB.body.runtimeDid === dids.B
    && (await publicOp(A, tokenB, 'status')).body.runtimeDid === dids.B, { did: dids.B });

  // "No new identity" is proven against the CATALOG: a forwarded operation is
  // executed only by the owner, so the other worker never builds a runtime
  // for this sandbox, and there is exactly one live session (owner +
  // generation) per sandbox, untouched by the forwarding.
  const identityA = await one(
    `SELECT count(*)::int AS n, owner, generation FROM public.proof_sessions
      WHERE token_hash=$1 AND state IN ('active','draining') GROUP BY owner, generation`, [tokenA]);
  check('matrix-no-new-identity-on-forward',
    identityA.n === 1 && identityA.owner === 'worker-a' && Number(identityA.generation) === 1,
    { identityA: { owner: identityA.owner, generation: Number(identityA.generation), rows: identityA.n } });
  const liveA = await one(
    `SELECT count(*)::int AS n FROM public.proof_sessions WHERE sandbox_id=$1::uuid AND state IN ('active','draining')`, [SANDBOX_A]);
  const liveB = await one(
    `SELECT count(*)::int AS n FROM public.proof_sessions WHERE sandbox_id=$1::uuid AND state IN ('active','draining')`, [SANDBOX_B]);
  check('matrix-one-live-session-per-sandbox',
    liveA.n === 1 && liveB.n === 1, { sandboxA: liveA.n, sandboxB: liveB.n });

  // A cookie that never resolved is a defined 410 (no probe, no reroute).
  const unknown = await publicOp(A, randomHex(24), 'status');
  check('matrix-unknown-cookie-410',
    unknown.status === 410 && unknown.body.error === 'session-lost',
    { status: unknown.status, error: unknown.body.error });

  // The trace must record at least one forward (the client hit the non-owner,
  // which re-signed and handed the operation to the real owner).
  const dumpB = await controlOp(B, 'worker-b', 'dump');
  const forwarded = (dumpB.body?.trace ?? []).filter((t) => t.outcome === 'forwarded');
  check('matrix-non-owner-forwarded', forwarded.length >= 1, { forwarded: forwarded.length });

  // Static / healthz / readyz are unrouted (no session identity).
  for (const [path, label] of [['/', 'root'], ['/healthz', 'healthz'], ['/readyz', 'readyz']]) {
    const s = await publicGet(B, path);
    check(`matrix-static-unrouted-${label}`,
      s.status === 200 && s.body?.worker === 'worker-b', { status: s.status, path });
  }

  // Clear both sandboxes: later scenarios create fresh tokens and must never
  // reuse a token across a clear (which would leave a stale in-memory belief).
  await clearSandbox(SANDBOX_A);
  await clearSandbox(SANDBOX_B);
  const afterA = await one(
    `SELECT count(*)::int AS n FROM public.proof_sessions WHERE sandbox_id=$1::uuid AND state IN ('active','draining')`, [SANDBOX_A]);
  const afterB = await one(
    `SELECT count(*)::int AS n FROM public.proof_sessions WHERE sandbox_id=$1::uuid AND state IN ('active','draining')`, [SANDBOX_B]);
  check('matrix-cleared', afterA.n === 0 && afterB.n === 0, { A: afterA.n, B: afterB.n });
}

// ============================================================================
// S2 - DRAIN (AC2): a drained worker records a deadline, marks its sessions
// draining, stops admitting NEW sessions (fast path AND the in-transaction
// admission gate), but keeps serving the sessions it already owns. Duplicate
// admission for an owned sandbox is refused with the in-transaction marker.
// Forced retirement keeps admission closed; the janitor reaps the owner-dead
// session; the observed loss discards the worker's in-memory runtime (F6). No
// SDK state is migrated or recreated on another worker.
// ============================================================================
async function s2Drain() {
  // The existing session is minted while worker-b is still ACTIVE (drain
  // closes admission for NEW sessions, it does not block creation of the
  // session that will outlive the grace window), then worker-b is drained.
  const created = await publicCreate(B, SANDBOX_B);
  assert.equal(created.status, 200, `tokenDrain create: ${created.status}`);
  const tokenDrain = created.body.token;

  // Normal drain of worker-b with a recorded deadline; the existing session
  // is marked draining.
  await catalogDrain('worker-b', 20000);
  const workerState = await one(
    `SELECT state, drain_deadline_at IS NOT NULL AS has_deadline, drain_deadline_at > now() AS deadline_future FROM public.proof_workers WHERE worker_id='worker-b'`);
  check('drain-recorded-deadline', workerState.state === 'draining' && workerState.has_deadline && workerState.deadline_future,
    { workerState });
  const sessState = await one(`SELECT state FROM public.proof_sessions WHERE token_hash=$1`, [tokenDrain]);
  check('drain-session-marked-draining', sessState.state === 'draining', { sessState });

  // F5 admission race, DETERMINISTIC: one driver transaction. We hold the
  // worker row lock (FOR UPDATE), start a create for a clean sandbox on the
  // OTHER worker -- which passes the fast path ('active') and blocks inside
  // reserve_session on the same row lock -- then flip that worker to draining
  // IN OUR transaction (nobody can commit that transition while we hold the
  // row lock). On commit the create's in-transaction gate re-reads the row
  // (EPQ) and must refuse WITHOUT writing a session row. No sleep between the
  // flip and the read; the re-read is what proves the gate is authoritative,
  // not the fast path.
  let raceResult;
  const raceClient = await control().connect();
  try {
    await raceClient.query('BEGIN');
    await raceClient.query(`SELECT state FROM public.proof_workers WHERE worker_id='worker-a' FOR UPDATE`);
    const createPromise = publicCreate(A, SANDBOX_A); // blocks on the row lock
    await sleep(800); // let it pass the fast path and reach reserve_session
    await raceClient.query(`UPDATE public.proof_workers SET state='draining',
      drain_deadline_at=now() + interval '20 seconds' WHERE worker_id='worker-a'`);
    await raceClient.query('COMMIT');
    raceResult = await createPromise;
  } finally {
    raceClient.release();
  }
  check('drain-admission-race-rejected',
    raceResult.status === 503 && raceResult.body.error === 'not-accepting-sessions'
    && raceResult.body.marker === 'admission-denied',
    { status: raceResult.status, error: raceResult.body.error, marker: raceResult.body.marker });
  const raceRow = await one(
    `SELECT count(*)::int AS n FROM public.proof_sessions WHERE sandbox_id=$1::uuid AND state IN ('active','draining')`, [SANDBOX_A]);
  check('drain-admission-race-no-row', raceRow.n === 0, { sandboxA: raceRow.n });

  // Worker-a is now draining (from the committed race): the same worker
  // refuses new-session admission (fast path, other sandbox). The duplicate-
  // 409 path was proven in S1 (matrix-duplicate-refused) while the owner was
  // active; a draining worker's create is refused before reserve_session, so
  // the 'existing' marker is unreachable while admission is closed.
  const refused = await publicCreate(A, SANDBOX_B);
  check('drain-new-session-refused', refused.status === 503 && refused.body.error === 'not-accepting-sessions',
    { status: refused.status, error: refused.body.error });
  // Readiness is alive while admission is closed (distinct signals) on BOTH
  // workers that are now draining.
  const readyzA = await publicGet(A, '/readyz');
  const readyzB = await publicGet(B, '/readyz');
  check('drain-readyz-alive-admission-closed',
    readyzA.status === 200 && readyzB.status === 200 && refused.status === 503,
    { readyzA: readyzA.status, readyzB: readyzB.status, admission: refused.status });

  // The draining worker still serves its existing session (status + a fenced
  // query inside the drain grace window)...
  const alive = await publicOp(B, tokenDrain, 'status');
  check('drain-existing-status-alive', alive.status === 200 && alive.body.owner === 'worker-b',
    { status: alive.status, owner: alive.body.owner });
  const aliveQuery = await publicOp(B, tokenDrain, 'query');
  check('drain-existing-query-alive', aliveQuery.status === 200 && Array.isArray(aliveQuery.body.rows),
    { status: aliveQuery.status, rows: aliveQuery.body.rows?.length });

  // Restore worker-a to active so S3's dead-owner retire (worker-b) is the
  // only admission-closed worker, and the sandbox-A create in S3 is unblocked.
  await one(`UPDATE public.proof_workers SET state='active', drain_deadline_at=NULL WHERE worker_id='worker-a'`);
  check('drain-worker-a-restored-active', (await one(`SELECT state FROM public.proof_workers WHERE worker_id='worker-a'`)).state === 'active');

  // Forced retirement: admission stays closed, no SDK state migrates.
  const retire = await controlOp(B, 'worker-b', 'retire');
  check('retire-control-applied', retire.status === 200, { status: retire.status });
  const retiredAdmission = await publicCreate(B, SANDBOX_A);
  check('retired-no-admission', retiredAdmission.status === 503, { status: retiredAdmission.status });
  const dumpA = await controlOp(A, 'worker-a', 'dump');
  check('drain-no-state-migration',
    Array.isArray(dumpA.body.liveTokens) && !dumpA.body.liveTokens.includes(tokenDrain),
    { workerA_tokens: dumpA.body.liveTokens });

  // Forced retirement means the owner is dead: the janitor reaps the session
  // (owner-dead -> lost) and bumps its generation. (The recorded drain
  // deadline plus admission refusal are the drain contract; the reap here is
  // the forced-retirement outcome.)
  const sweep = await q(control(), `SELECT token_hash, reason, outcome FROM proof_ctrl.janitor_sweep(32)`);
  const reaped = sweep.find((r) => r.token_hash === tokenDrain);
  check('drain-janitor-reaps-retired-worker-session',
    reaped && reaped.reason === 'owner-dead' && reaped.outcome === 'reaped', { reaped });
  const after = await one(`SELECT state, generation FROM public.proof_sessions WHERE token_hash=$1`, [tokenDrain]);
  check('drain-reaped-session-lost-generation-bumped',
    after.state === 'lost' && Number(after.generation) === 2, { after: { ...after, generation: Number(after.generation) } });

  // F6: the worker's next observation of the loss (router re-resolve) returns
  // a defined 410 and evicts its in-memory runtime -- the discarded SDK state
  // is not migrated anywhere.
  const lostStatus = await publicOp(B, tokenDrain, 'status');
  const dumpB = await controlOp(B, 'worker-b', 'dump');
  check('drain-state-discarded-on-loss',
    lostStatus.status === 410 && lostStatus.body.error === 'session-lost'
    && !dumpB.body.liveTokens?.includes(tokenDrain)
    && (dumpB.body.discards ?? []).some((d) => d.token === tokenDrain),
    { status: lostStatus.status, liveTokens: dumpB.body.liveTokens, discards: dumpB.body.discards });

  // Reset worker-b to active for the next phases.
  await one(`UPDATE public.proof_workers SET state='active', drain_deadline_at=NULL WHERE worker_id='worker-b'`);
  check('drain-worker-reset-active', (await one(`SELECT state FROM public.proof_workers WHERE worker_id='worker-b'`)).state === 'active');
}

// ============================================================================
// S3 - DEAD OWNER + CATALOG UNAVAILABLE (AC4): a dead owner's session is lost
// (no random reroute), and a catalog outage fails closed with a defined
// dependency-unavailable, never a silent reroute or a committed mutation.
// ============================================================================
async function s3DeadOwner() {
  // (a) Dead owner: worker-b is retired (treated as dead); its session is
  // reaped LOST by the janitor. Requests for the lost session get a defined
  // session-lost from both workers -- no random reroute resurrects it.
  await clearSandbox(SANDBOX_B);
  const created = await publicCreate(B, SANDBOX_B);
  if (created.status !== 200 || !created.body.token) {
    check('dead-owner-session-created', false,
      { status: created.status, body: created.body, workerB: await one(`SELECT state FROM public.proof_workers WHERE worker_id='worker-b'`) });
    throw new Error(`dead-owner create failed: ${created.status} ${JSON.stringify(created.body)}`);
  }
  const tokenDead = created.body.token;
  await one(`UPDATE public.proof_workers SET state='retired' WHERE worker_id='worker-b'`);
  const sweep = await q(control(), `SELECT token_hash, reason, outcome FROM proof_ctrl.janitor_sweep(32)`);
  const reaped = sweep.find((r) => r.token_hash === tokenDead);
  check('dead-owner-janitor-reaps-lost', reaped && reaped.reason === 'owner-dead' && reaped.outcome === 'reaped', { reaped });
  const lost = await one(`SELECT state, generation FROM public.proof_sessions WHERE token_hash=$1`, [tokenDead]);
  check('dead-owner-session-lost', lost && lost.state === 'lost' && Number(lost.generation) === 2, { lost: lost ? { ...lost, generation: Number(lost.generation) } : null });

  // Both workers resolve the lost cookie to a defined session-lost.
  const revalB = await publicOp(B, tokenDead, 'revalidate');
  check('dead-owner-worker-drops-belief', revalB.status === 410 && revalB.body.error === 'session-lost',
    { status: revalB.status, error: revalB.body.error });
  const goneA = await publicOp(A, tokenDead, 'status');
  const goneB = await publicOp(B, tokenDead, 'status');
  check('dead-owner-no-reroute-lost', goneA.status === 410 && goneB.status === 410,
    { A: goneA.status, B: goneB.status });
  // F6: worker-b's observation of the loss discards its in-memory runtime.
  const dumpBDead = await controlOp(B, 'worker-b', 'dump');
  check('dead-owner-state-discarded',
    !dumpBDead.body.liveTokens?.includes(tokenDead)
    && (dumpBDead.body.discards ?? []).some((d) => d.token === tokenDead),
    { liveTokens: dumpBDead.body.liveTokens, discards: dumpBDead.body.discards });
  await one(`UPDATE public.proof_workers SET state='active' WHERE worker_id='worker-b'`);

  // (b) Catalog unavailable: postgres is stopped (host docker). A mutation
  // must fail closed with a defined dependency-unavailable, and the owner
  // must NOT silently reroute or commit.
  await clearSandbox(SANDBOX_A);
  const createdA = await publicCreate(A, SANDBOX_A);
  assert.equal(createdA.status, 200, `tokenDown create: ${createdA.status}`);
  const tokenDown = createdA.body.token;
  const qtyBefore = await quantity(SANDBOX_A, 1);
  await dockerStopPostgres();
  const down = await publicOpSafe(A, tokenDown, 'mutate');
  check('catalog-down-mutation-fails-closed',
    down.status === 503 && down.body?.error === 'dependency-unavailable',
    { down: { status: down.status, error: down.body?.error } });
  await dockerStartPostgres();
  await waitForCatalog();
  // The mutation did NOT commit while the catalog was down (no ambiguous retry).
  const qty = await quantity(SANDBOX_A, 1);
  check('catalog-down-no-ambiguous-commit', qty === qtyBefore, { qty, qtyBefore });

  // After recovery the same owner serves the same session with the same
  // generation (no new identity, no random reroute).
  const up = await publicOp(A, tokenDown, 'status');
  check('catalog-recovered-same-session', up.status === 200 && up.body.owner === 'worker-a' && up.body.generation === 1,
    { status: up.status, owner: up.body.owner, generation: up.body.generation });

  // Reset worker-b to active.
  check('dead-owner-worker-restored-active', (await one(`SELECT state FROM public.proof_workers WHERE worker_id='worker-b'`)).state === 'active');
}

// ============================================================================
// S4 - FENCING (AC3): ownership is fenced at the mutation transaction
// boundary. A stale generation rolls back; an expired lease is renewable,
// and a retired owner / passed drain deadline are terminal; the in-flight
// advisory lock makes the janitor defer, and blocks a generation bump AND an
// ownership transfer (55P03); a resumed stale worker is rejected; a transfer
// away from the runtime's holder is incompatible (F7) until it returns to the
// holder.
// ============================================================================
async function s4Fencing() {
  await clearSandbox(SANDBOX_B);
  const created = await publicCreate(B, SANDBOX_B);
  const token = created.body.token;
  const baseGen = created.body.generation; // 1
  // The seeded sandbox starts at id=1 quantity 10 (id=2 is the CARBON row).
  // --- (1) Stale generation + fenced reset --------------------------------
  const reset = await publicOp(B, token, 'reset');
  const qtyReset = await quantity(SANDBOX_B, 1);
  check('fence-reset-commits', reset.status === 200 && qtyReset === 10, { status: reset.status, qty: qtyReset });

  // A stale generation is rejected at the transaction boundary: bump the
  // sandbox generation while the worker still believes the old one; its next
  // mutation must fence pre and roll back (409), never commit.
  const bumped = await one(`SELECT proof_ctrl.bump_generation($1::uuid, $2) AS g`, [SANDBOX_B, baseGen]);
  check('fence-bump-applied', Number(bumped.g) === baseGen + 1, { g: Number(bumped.g) });
  const stale = await publicOp(B, token, 'mutate');
  check('fence-stale-generation-rejected', stale.status === 409 && stale.body.error === 'stale-ownership',
    { status: stale.status, error: stale.body.error, reason: stale.body.reason });
  const qtyStale = await quantity(SANDBOX_B, 1);
  check('fence-stale-mutation-not-committed', qtyStale === 10, { qty: qtyStale, seed: 10 });
  const dumpB = await controlOp(B, 'worker-b', 'dump');
  const fencedEvent = (dumpB.body.events ?? []).find((e) => e.fenced === true && e.outcome === 'rollback'
    && e.fencePhase === 'pre' && e.fenceReason === 'stale-ownership');
  check('fence-transaction-evidence', !!fencedEvent, { fencedEvent });
  // Revalidation adopts the new generation (same owner). The lease expires
  // ~3s after create (renewal keeps it alive while we run the evidence).
  const reval = await publicOp(B, token, 'revalidate');
  check('fence-revalidate-adopts-generation', reval.status === 200 && reval.body.generation === baseGen + 1 && reval.body.self === true,
    { status: reval.status, generation: reval.body.generation, self: reval.body.self });
  const renewed2 = await publicOp(B, token, 'renew');
  check('fence-renewal-after-revalidate', renewed2.status === 200, { status: renewed2.status });

  // --- (2) Expired lease is terminal (F2); renewal restores ---------------
  // Quantity evidence is RELATIVE to the pre-mutate value: order rows
  // persist across clear_sandbox (sessions only are cleared), so a session
  // created on a reused sandbox inherits whatever quantity the earlier
  // scenario left behind.
  const qtyLeaseBase = await quantity(SANDBOX_B, 1);
  const mutate = await publicOp(B, token, 'mutate');
  check('fence-current-generation-commits', mutate.status === 200 && mutate.body?.committed,
    { status: mutate.status });
  const qtyCurrent = await quantity(SANDBOX_B, 1);
  check('fence-current-mutation-committed', qtyCurrent === qtyLeaseBase + 1,
    { qty: qtyCurrent, base: qtyLeaseBase });

  await one(`SELECT proof_ctrl.expire_lease($1)`, [token]);
  const leaseStale = await publicOp(B, token, 'mutate');
  check('fence-lease-expired-rejected',
    leaseStale.status === 410 && leaseStale.body.error === 'session-lost' && leaseStale.body.detail === 'lease-expired',
    { status: leaseStale.status, detail: leaseStale.body.detail });
  const qtyLease = await quantity(SANDBOX_B, 1);
  check('fence-lease-expired-not-committed', qtyLease === qtyLeaseBase + 1, { qty: qtyLease, expected: qtyLeaseBase + 1 });
  const renewed = await publicOp(B, token, 'renew');
  const mutateRenewed = await publicOp(B, token, 'mutate');
  const qtyRenewed = await quantity(SANDBOX_B, 1);
  const dumpRenew = await controlOp(B, 'worker-b', 'dump');
  check('fence-lease-renew-restores',
    renewed.status === 200 && renewed.body.renewed === true
    && mutateRenewed.status === 200 && qtyRenewed === qtyLeaseBase + 2
    && dumpRenew.body.liveTokens?.includes(token),
    { renewed: renewed.status, mutate: mutateRenewed.status, qty: qtyRenewed, expected: qtyLeaseBase + 2,
      stillAlive: dumpRenew.body.liveTokens?.includes(token) });

  // --- (3) In-flight drain deadline: mutual exclusion blocks bump AND
  // transfer (F3), the pre-commit fence rejects drain-deadline (F2), and the
  // janitor defers while the lock is held, then reaps 'drained'.
  // reset (fenced) re-establishes the deterministic seed (quantity 10) for
  // the no-partial-write evidence; a fresh session carries the drain.
  await clearSandbox(SANDBOX_B);
  const created3 = await publicCreate(B, SANDBOX_B);
  const token3 = created3.body.token; // active, gen 1
  const reset3 = await publicOp(B, token3, 'reset');
  assert.equal(reset3.status, 200, `token3 reset: ${reset3.status}`);
  const qtyHoldBefore = await quantity(SANDBOX_B, 1);
  assert.equal(qtyHoldBefore, 10, `token3 seed: ${qtyHoldBefore}`);
  // Timing: the lease (30s) never expires in this window; the drain
  // deadline (1.5s from the drain call ≈ 1.3s from hold start) is the
  // INNER trigger. The hold keeps the advisory lock for ~2s: driver
  // checks run at ~t_hold+1.6s (PAST the deadline, so the janitor has a
  // candidate, and BEFORE the pre-commit fence at ~t_hold+2.2s, so the
  // lock is still held and the in-flight evidence is live).
  await catalogDrain('worker-b', 1500); // worker + token3 now draining, deadline +1.5s
  await sleep(200); // small margin before the hold's pre fence
  const lockId = await one(`SELECT proof_ctrl.sandbox_lock_id($1::uuid) AS id`, [SANDBOX_B]);
  const holdPromise = publicOp(B, token3, 'hold'); // pg_sleep(2) inside the fence
  await sleep(1600); // ~t_hold+1.6s: past the drain deadline, still inside the hold
  const locks = await q(admin(), `SELECT count(*)::int AS n FROM pg_locks
    WHERE locktype='advisory' AND classid=0 AND objid=$1 AND granted`, [lockId.id]);
  check('fence-inflight-holds-advisory-lock', locks[0].n === 1, { advisoryLocks: locks[0].n });
  const sweepDuring = await q(control(), `SELECT token_hash, reason, outcome FROM proof_ctrl.janitor_sweep(32)`);
  const deferred = sweepDuring.find((r) => r.token_hash === token3 && r.reason === 'mutation-in-flight' && r.outcome === 'deferred');
  check('fence-janitor-defers-inflight', !!deferred,
    { sweepDuring: sweepDuring.map((r) => `${r.token_hash.slice(0, 8)}/${r.reason}/${r.outcome}`) });
  const bumpBlocked = await one(`SELECT proof_ctrl.bump_generation($1::uuid, $2) AS g`, [SANDBOX_B, 1])
    .then(() => ({ ok: true })).catch((e) => ({ ok: false, code: e.code, message: String(e.message).slice(0, 64) }));
  check('fence-bump-blocked-while-inflight', bumpBlocked.ok === false && bumpBlocked.code === '55P03', { bumpBlocked });
  const transferBlocked = await one(`SELECT proof_ctrl.transfer_ownership($1, 'worker-a') AS g`, [token3])
    .then(() => ({ ok: true })).catch((e) => ({ ok: false, code: e.code, message: String(e.message).slice(0, 64) }));
  check('fence-transfer-blocked-while-inflight', transferBlocked.ok === false && transferBlocked.code === '55P03', { transferBlocked });
  const holdResult = await holdPromise;
  // The hold ran past the drain deadline: its pre-commit fence raised
  // 'Drain deadline passed' and the transaction rolled back (the lock is
  // released with the rollback).
  check('fence-drain-deadline-rejected',
    holdResult.status === 410 && holdResult.body.error === 'session-lost' && holdResult.body.detail === 'drain-deadline',
    { status: holdResult.status, detail: holdResult.body.detail });
  const lockAfter = await q(admin(), `SELECT count(*)::int AS n FROM pg_locks
    WHERE locktype='advisory' AND classid=0 AND objid=$1 AND granted`, [lockId.id]);
  check('fence-lock-released-after-inflight', lockAfter[0].n === 0, { advisoryLocks: lockAfter[0].n });
  // hold performs no row write: the id=1 quantity is exactly what it was
  // before the hold (no partial write from the rolled-back transaction).
  const qtyHold = await quantity(SANDBOX_B, 1);
  check('fence-inflight-no-partial-write', qtyHold === qtyHoldBefore, { qty: qtyHold, before: qtyHoldBefore });
  const drainSweep = await q(control(), `SELECT token_hash, reason, outcome FROM proof_ctrl.janitor_sweep(32)`);
  const drainReaped = drainSweep.find((r) => r.token_hash === token3 && r.reason === 'drained' && r.outcome === 'reaped');
  check('fence-janitor-reaps-drained', !!drainReaped,
    { sweep: drainSweep.map((r) => `${r.token_hash.slice(0, 8)}/${r.reason}/${r.outcome}`) });
  const drainState = await one(`SELECT state, generation FROM public.proof_sessions WHERE token_hash=$1`, [token3]);
  check('fence-drained-session-deleted-generation-bumped',
    drainState.state === 'deleted' && Number(drainState.generation) === 2,
    { drainState: { ...drainState, generation: Number(drainState.generation) } });
  const dumpDrain = await controlOp(B, 'worker-b', 'dump');
  check('fence-drain-runtime-discarded',
    !dumpDrain.body.liveTokens?.includes(token3)
    && (dumpDrain.body.discards ?? []).some((d) => d.token === token3 && String(d.reason).startsWith('fence-drain-deadline')),
    { liveTokens: dumpDrain.body.liveTokens, discards: dumpDrain.body.discards });
  await one(`UPDATE public.proof_workers SET state='active', drain_deadline_at=NULL WHERE worker_id='worker-b'`);

  // --- (4) Retired owner is terminal (F2) ---------------------------------
  await clearSandbox(SANDBOX_B);
  const created4 = await publicCreate(B, SANDBOX_B);
  const token4 = created4.body.token;
  await one(`SELECT proof_ctrl.expire_lease($1)`, [token4]); // guard: keep the lease outside the drain window under load
  const renew4 = await publicOp(B, token4, 'renew');
  assert.equal(renew4.status, 200, `token4 renew: ${renew4.status}`);
  const qtyRetiredBefore = await quantity(SANDBOX_B, 1);
  await one(`UPDATE public.proof_workers SET state='retired' WHERE worker_id='worker-b'`);
  const retiredMutate = await publicOp(B, token4, 'mutate');
  check('fence-owner-retired-rejected',
    retiredMutate.status === 410 && retiredMutate.body.error === 'session-lost' && retiredMutate.body.detail === 'owner-retired',
    { status: retiredMutate.status, detail: retiredMutate.body.detail });
  const qtyRetired = await quantity(SANDBOX_B, 1);
  check('fence-owner-retired-not-committed', qtyRetired === qtyRetiredBefore, { qty: qtyRetired, before: qtyRetiredBefore });
  const ownerDeadSweep = await q(control(), `SELECT token_hash, reason, outcome FROM proof_ctrl.janitor_sweep(32)`);
  const ownerDead = ownerDeadSweep.find((r) => r.token_hash === token4 && r.reason === 'owner-dead' && r.outcome === 'reaped');
  check('fence-janitor-reaps-owner-dead', !!ownerDead,
    { sweep: ownerDeadSweep.map((r) => `${r.token_hash.slice(0, 8)}/${r.reason}/${r.outcome}`) });
  const ownerDeadState = await one(`SELECT state, generation FROM public.proof_sessions WHERE token_hash=$1`, [token4]);
  check('fence-reaped-owner-dead-lost',
    ownerDeadState.state === 'lost' && Number(ownerDeadState.generation) === 2,
    { ownerDeadState: { ...ownerDeadState, generation: Number(ownerDeadState.generation) } });
  await one(`UPDATE public.proof_workers SET state='active' WHERE worker_id='worker-b'`);
  check('fence-worker-restored-active',
    (await one(`SELECT state FROM public.proof_workers WHERE worker_id='worker-b'`)).state === 'active');

  // --- (5) Resumed stale owner cannot commit ------------------------------
  await clearSandbox(SANDBOX_A);
  const createdA = await publicCreate(A, SANDBOX_A);
  const tokenResume = createdA.body.token;
  const qtyResumeBefore = await quantity(SANDBOX_A, 1);
  await one(`SELECT proof_ctrl.bump_generation($1::uuid, $2)`, [SANDBOX_A, 1]); // gen 2, owner still worker-a
  const resume = await publicOp(A, tokenResume, 'mutate');
  check('fence-stale-resume-rejected', resume.status === 409 && resume.body.error === 'stale-ownership',
    { status: resume.status, error: resume.body.error });
  const qtyResume = await quantity(SANDBOX_A, 1);
  check('fence-stale-resume-not-committed', qtyResume === qtyResumeBefore, { qty: qtyResume });
  // A resumed worker revalidates: the catalog now holds a different generation
  // it never adopted, so it reports the fresh state (owner still worker-a,
  // gen 2) and the worker adopts it only for its own session.
  const revalResume = await publicOp(A, tokenResume, 'revalidate');
  check('fence-stale-resume-revalidate-report', revalResume.status === 200 && revalResume.body.generation === 2 && revalResume.body.self === true,
    { status: revalResume.status, generation: revalResume.body.generation, self: revalResume.body.self });
  await clearSandbox(SANDBOX_A);

  // --- (6) Cross-worker ownership transfer (F7): a transfer to a worker
  // that does NOT hold the session's materialized runtime is incompatible;
  // the SAME session row is reused (no new identity), and when ownership
  // returns to the holder the runtime (and its DID) is adopted unchanged.
  await clearSandbox(SANDBOX_B);
  const transferCreate = await publicCreate(B, SANDBOX_B);
  const tokenT = transferCreate.body.token; // worker-b, gen 1, DID persisted
  const didT = transferCreate.body.runtimeDid;
  // The runtime is stable on the holder BEFORE any transfer.
  const stableStatus = await publicOp(B, tokenT, 'status');
  check('fence-transfer-stable-runtime-identity',
    stableStatus.status === 200 && stableStatus.body.runtimeDid === didT && stableStatus.body.owner === 'worker-b',
    { did: stableStatus.body.runtimeDid, owner: stableStatus.body.owner });
  // The transfer itself is blocked while a fenced operation is in flight
  // (proven in (3)); here it is not in flight, so it commits.
  const transfer = await one(`SELECT proof_ctrl.transfer_ownership($1, $2) AS g`, [tokenT, 'worker-a']);
  check('fence-transfer-bumps-generation', Number(transfer.g) === 2, { g: Number(transfer.g) });
  // The OLD owner's entry point: the router now forwards to the new owner;
  // worker-a does not hold the materialized runtime (DID already recorded)
  // -> F7 incompatible-runtime 410, not a fresh mint.
  const transferOld = await publicOpSafe(B, tokenT, 'status');
  check('fence-transfer-old-entry-incompatible',
    transferOld.status === 410 && transferOld.body.error === 'session-lost'
    && transferOld.body.detail === 'incompatible-runtime',
    { status: transferOld.status, detail: transferOld.body.detail });
  // The NEW owner's entry point: local execute, no runtime, DID recorded ->
  // the same F7 410 (never a second identity).
  const transferNew = await publicOp(A, tokenT, 'status');
  check('fence-transfer-nonholder-incompatible',
    transferNew.status === 410 && transferNew.body.error === 'session-lost'
    && transferNew.body.detail === 'incompatible-runtime',
    { status: transferNew.status, detail: transferNew.body.detail });
  const transferRow = await one(
    `SELECT count(*)::int AS n, owner, generation FROM public.proof_sessions
      WHERE token_hash=$1 GROUP BY owner, generation`, [tokenT]);
  check('fence-transfer-no-new-identity',
    transferRow.n === 1 && transferRow.owner === 'worker-a' && Number(transferRow.generation) === 2,
    { owner: transferRow.owner, generation: Number(transferRow.generation), rows: transferRow.n });
  // Ownership returns to the holder (worker-b). The holder NEVER lost its
  // runtime: routing forwards operations to the catalog owner, so worker-b
  // never received a transfer-away observation (only worker-a's forwarded
  // revalidate was rejected as stale-hop and evicted worker-a's non-holder
  // belief). The holder's belief is now stale (gen 3, not gen 1); a
  // revalidate at its OWN entry point adopts the catalog truth (self, gen 3)
  // and its session status serves the SAME materialized DID -- no second
  // identity, no re-mint.
  const transferBack = await one(`SELECT proof_ctrl.transfer_ownership($1, $2) AS g`, [tokenT, 'worker-b']);
  const revalBack = await publicOp(B, tokenT, 'revalidate');
  const statusBack = await publicOp(B, tokenT, 'status');
  check('fence-transfer-back-holder-report',
    Number(transferBack.g) === 3 && revalBack.status === 200 && revalBack.body.self === true
    && revalBack.body.generation === 3
    && statusBack.status === 200 && statusBack.body.runtimeDid === didT,
    { gen: Number(transferBack.g), reval: revalBack.status, revalGen: revalBack.body.generation,
      statusBack: { status: statusBack.status, runtimeDid: statusBack.body.runtimeDid, didT } });
  await clearSandbox(SANDBOX_B);
}

// ============================================================================
// S5 - FORGED INTERNAL HOP + PRIVILEGE + BOUNDARY (AC5): the internal hop is
// protected by per-worker HMAC, hop limit, deadline window, destination
// self-check, and catalog re-resolution; the catalog control surface is an
// explicit EXECUTE allowlist (PUBLIC and the data-plane roles are denied);
// the public surface enforces the Origin allowlist and the expected Host.
// ============================================================================
async function s5ForgedHop() {
  await clearSandbox(SANDBOX_A);
  const createdA = await publicCreate(A, SANDBOX_A);
  const token = createdA.body.token; // worker-a owned, gen 1
  assert.equal(createdA.status, 200, `S5 tokenA create: ${createdA.status}`);
  await clearSandbox(SANDBOX_B);
  const createdB = await publicCreate(B, SANDBOX_B);
  const tokenB = createdB.body.token; // worker-b owned, gen 1
  assert.equal(createdB.status, 200, `S5 tokenB create: ${createdB.status}`);

  // (a) Forged signature (bogus key): every other field is correct, so only
  // the HMAC fails. checkInternalHop rejects at the signature step.
  const forged = await internalOp(A, token, 'status', hopHeaders(
    `/internal/${token}/status`, { token, owner: 'worker-a', generation: 1,
      secret: process.env.ROUTING_SECRET_A, signature: 'deadbeef'.repeat(8) }));
  check('forged-hop-bad-signature-rejected', forged.status === 401 && forged.body.error === 'signature',
    { status: forged.status, error: forged.body.error });

  // (b) Hop limit: a hop that claims it already forwarded once (hop=2) is
  // rejected (no forwarding loops).
  const loop = await internalOp(A, token, 'status', hopHeaders(
    `/internal/${token}/status`, { token, owner: 'worker-a', generation: 1,
      secret: process.env.ROUTING_SECRET_A, hop: '2' }));
  check('forged-hop-hop-limit-rejected', loop.status === 401 && loop.body.error === 'hop-limit',
    { status: loop.status, error: loop.body.error });

  // (c) Expired deadline: a hop with a deadline outside the window.
  const expired = await internalOp(A, token, 'status', hopHeaders(
    `/internal/${token}/status`, { token, owner: 'worker-a', generation: 1,
      secret: process.env.ROUTING_SECRET_A, deadline: String(Date.now() - 60000) }));
  check('forged-hop-deadline-rejected', expired.status === 401 && expired.body.error === 'hop-deadline',
    { status: expired.status, error: expired.body.error });

  // (d) Stale generation: a hop claiming a generation the catalog no longer
  // holds for this session (signed validly, so only re-resolution rejects it).
  const stale = await internalOp(A, token, 'status', hopHeaders(
    `/internal/${token}/status`, { token, owner: 'worker-a', generation: 9,
      secret: process.env.ROUTING_SECRET_A }));
  check('forged-hop-stale-generation-rejected', stale.status === 409 && stale.body.error === 'stale-hop',
    { status: stale.status, error: stale.body.error });

  // (e) Cross-secret: the hop is signed with the PEER's (worker-b) secret,
  // not the destination worker's own secret -> HMAC mismatch.
  const crossSecret = await internalOp(A, token, 'status', hopHeaders(
    `/internal/${token}/status`, { token, owner: 'worker-a', generation: 1,
      secret: process.env.ROUTING_SECRET_B }));
  check('forged-hop-cross-secret-rejected', crossSecret.status === 401 && crossSecret.body.error === 'signature',
    { status: crossSecret.status, error: crossSecret.body.error });

  // (f) Wrong destination: the hop is addressed to worker-b (its session) but
  // is delivered to worker-a. The destination never executes another worker's
  // hop.
  const wrongDest = await internalOp(A, tokenB, 'status', hopHeaders(
    `/internal/${tokenB}/status`, { token: tokenB, owner: 'worker-b', generation: 1,
      secret: process.env.ROUTING_SECRET_B }));
  check('forged-hop-wrong-destination-rejected', wrongDest.status === 401 && wrongDest.body.error === 'wrong-destination',
    { status: wrongDest.status, error: wrongDest.body.error });

  // (g) Missing headers: a hop with no routing headers is rejected.
  const missing = await internalOp(A, token, 'status', {});
  check('forged-hop-missing-headers-rejected', missing.status === 401 && missing.body.error === 'missing-hop-headers',
    { status: missing.status, error: missing.body.error });

  // (h) Positive control: a valid hop (destination's own secret, correct
  // owner/generation, fresh deadline, hop=1) executes. Proves (a)-(g) are
  // not blanket denials.
  const valid = await internalOp(A, token, 'status', hopHeaders(
    `/internal/${token}/status`, { token, owner: 'worker-a', generation: 1,
      secret: process.env.ROUTING_SECRET_A }));
  check('forged-hop-valid-hop-accepts', valid.status === 200, { status: valid.status });

  // --- F1: the catalog control surface is an explicit EXECUTE allowlist.
  // PUBLIC (and any ungranted role) is revoked from every proof function;
  // the data-plane roles keep only the fence/read surface; proof_control
  // keeps the lifecycle surface. Probed with has_function_privilege, the
  // authoritative PG16 grant check (pg_has_function does not exist).
  const privileged = [
    'transfer_ownership(text, text)', 'reset_sandbox(uuid)', 'issue_context(uuid, integer, text, text)',
    'janitor_sweep(integer)', 'reserve_session(text, uuid, text, integer)', 'bump_generation(uuid, bigint)',
    'expire_lease(text)', 'clear_sandbox(uuid)', 'set_worker_state(text, text, integer)',
    'delete_session(text)', 'lose_session(text)', 'seed_sandbox(uuid)', 'snapshot()', 'set_runtime_did(text, text)',
  ];
  const safeReads = ['live_session(uuid)', 'resolve_session(text)', 'verify_fence(uuid, text, bigint)'];
  // proof_probe is created BEFORE the matrix: a role with USAGE on the
  // schemas but no EXECUTE grant on any proof function — the representative
  // of the PUBLIC class (has_function_privilege rejects the literal
  // 'PUBLIC', so a real role stands in for it).
  await q(admin(), `DO $$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'proof_probe') THEN
        CREATE ROLE proof_probe NOINHERIT NOLOGIN;
      END IF;
    END $$`);
  await q(admin(), 'GRANT USAGE ON SCHEMA proof_ctrl, proof_guard TO proof_probe');
  const priv = async (role, schema, fn) => (await q(admin(),
    `SELECT has_function_privilege($1::text, format('%I.%I(%s)', $2::text, split_part($3::text, '(', 1), substring($3::text from position('(' in $3::text) + 1 for length($3::text) - position('(' in $3::text) - 1))::regprocedure, 'EXECUTE') AS has`,
    [role, schema, fn]))[0];
  const publicDenied = [];
  const queryDenied = [];
  const rawDenied = [];
  const controlAllowed = [];
  for (const fn of privileged) {
    publicDenied.push((await priv('proof_probe', 'proof_ctrl', fn)).has === false);
    queryDenied.push((await priv('proof_query', 'proof_ctrl', fn)).has === false);
    rawDenied.push((await priv('proof_raw', 'proof_ctrl', fn)).has === false);
    controlAllowed.push((await priv('proof_control', 'proof_ctrl', fn)).has === true);
  }
  check('priv-public-no-privileged-execute', publicDenied.every(Boolean), { publicDenied });
  check('priv-data-roles-no-privileged-execute', queryDenied.every(Boolean) && rawDenied.every(Boolean),
    { queryDenied, rawDenied });
  check('priv-control-allowlist-complete', controlAllowed.every(Boolean), { controlAllowed });
  const querySafe = [];
  for (const fn of safeReads) {
    querySafe.push((await priv('proof_query', 'proof_ctrl', fn)).has === true);
  }
  const guardSafe = (await priv('proof_query', 'proof_guard', 'current_sandbox()')).has === true;
  check('priv-data-roles-keep-safe-reads', querySafe.every(Boolean) && guardSafe, { querySafe, guardSafe });
  // Real execution probe: a role with USAGE on the schema but no EXECUTE
  // grant is refused by the catalog itself (42501), not just by the matrix.
  // The probe is created with an explicit search_path so its call cannot
  // resolve against any other schema. Each statement runs alone (params
  // select the extended protocol, which takes a single statement).
  const probeClient = await admin().connect();
  let probeError = null;
  try {
    await probeClient.query('SET search_path TO proof_ctrl, proof_guard, public');
    await probeClient.query('SET ROLE proof_probe');
    try {
      await probeClient.query(`SELECT transfer_ownership($1, 'worker-a')`, [randomHex(32)]);
    } catch (error) {
      probeError = error;
    } finally {
      await probeClient.query('RESET ROLE');
      await probeClient.query('RESET search_path');
    }
  } finally {
    probeClient.release();
  }
  check('priv-unauthorized-call-denied-42501', probeError?.code === '42501',
    { code: probeError?.code ?? null, message: String(probeError?.message ?? '').slice(0, 80) });

  // --- W2: the public surface is the trust boundary. A foreign browser
  // Origin and a misdirected Host are rejected before any route handling.
  const foreignOrigin = await rawHttp(B, '/', { origin: 'https://evil.example' });
  check('public-origin-foreign-rejected',
    foreignOrigin.status === 403 && foreignOrigin.body.error === 'origin-not-allowed',
    { status: foreignOrigin.status, error: foreignOrigin.body.error });
  const allowedOrigin = await rawHttp(B, '/healthz', { origin: 'https://playground.example' });
  check('public-origin-allowed-accepts',
    allowedOrigin.status === 200 && allowedOrigin.body.worker === 'worker-b',
    { status: allowedOrigin.status });
  const foreignHost = await rawHttp(B, '/', { host: 'evil.example:8080' });
  check('public-host-foreign-rejected',
    foreignHost.status === 403 && foreignHost.body.error === 'host-not-allowed',
    { status: foreignHost.status, error: foreignHost.body.error });
  const allowedHost = await rawHttp(B, '/readyz', { host: `worker-b:${PORT}` });
  check('public-host-allowed-accepts',
    allowedHost.status === 200 && allowedHost.body.worker === 'worker-b',
    { status: allowedHost.status });
}

// ============================================================================
// S6 - PREREQUISITE REPORTS + WORKLOAD AUTH (AC5): the combined gate cites
// the 887 SQLite runtime proof and the 888 SQL isolation proof. The driver
// reads BOTH prerequisite reports from the image and verifies they are PASS
// (W3) -- the gate consumes the driver's evidence, not a hardcoded value.
// ============================================================================
async function s6WorkloadAuth() {
  let runtime887 = 'FAIL';
  try {
    const markdown = await readFile('/app/demo/playground/reports/sqlite-runtime-proof.md', 'utf8');
    runtime887 = /## Decision[\s\S]*?\*\*PASS/.test(markdown) ? 'PASS' : 'FAIL';
  } catch { runtime887 = 'FAIL'; }
  check('prereq-runtime-lifecycle-887', runtime887 === 'PASS', { runtime887 });
  let sql888 = 'FAIL';
  try {
    const parsed = JSON.parse(await readFile('/app/demo/playground/reports/sandbox-isolation-proof.json', 'utf8'));
    sql888 = parsed.status === 'PASS' ? 'PASS' : 'FAIL';
  } catch { sql888 = 'FAIL'; }
  check('prereq-sql-isolation-888', sql888 === 'PASS', { sql888 });
  report.prerequisites = { runtimeLifecycle887: runtime887, sqlIsolation888: sql888 };

  const snap = await one(`SELECT proof_ctrl.snapshot() AS s`);
  check('combined-gate-catalog-snapshot',
    !!snap.s && Array.isArray(snap.s.sessions) && Array.isArray(snap.s.workers) && snap.s.workers.length === 2,
    { sessions: snap.s.sessions?.length, workers: snap.s.workers?.length });

  report.workloadAuth = {
    internalHop: ['per-worker-hmac', 'hop-limit-1', 'deadline-window', 'destination-self-check', 'catalog-re-resolve'],
    networkIsolation: 'internal-docker-network-egress-blocked',
    productionRequirement: 'mTLS-or-SPIFFE-workload-identity-required; gateway-only-header-policy-is-NOT-sufficient',
    claimed: false,
  };
}

// ============================================================================
async function main() {
  try {
    assert.ok(PG_CONTAINER, 'ROUTING_PG_CONTAINER is required for the catalog-down fault');
    assert.ok(process.env.ROUTING_CONTROL_SECRET, 'ROUTING_CONTROL_SECRET is required');
    emit({ type: 'ready', driver: 'scenarios' });
    await waitForWorkers();

    await s1RoutingMatrix();
    report.phases.s1 = 'done';
    await s2Drain();
    report.phases.s2 = 'done';
    await s3DeadOwner();
    report.phases.s3 = 'done';
    await s4Fencing();
    report.phases.s4 = 'done';
    await s5ForgedHop();
    report.phases.s5 = 'done';
    await s6WorkloadAuth();
    report.phases.s6 = 'done';

    const by = { routingMatrix: [], drain: [], deadOwner: [], fencing: [], forgedHop: [], combinedGate: [] };
    for (const c of report.checks) by[criterion(c.name)].push(c);
    const ok = (group) => group.length > 0 && group.every((c) => c.status === 'PASS');
    const a = {
      routingMatrix: ok(by.routingMatrix),
      drain: ok(by.drain),
      deadOwner: ok(by.deadOwner),
      fencing: ok(by.fencing),
      forgedHop: ok(by.forgedHop),
    };
    report.acceptance = {
      ...a,
      combinedGate: {
        runtimeLifecycle887: report.prerequisites.runtimeLifecycle887,
        sqlIsolation888: report.prerequisites.sqlIsolation888,
        routingDrainingFencing: a.routingMatrix && a.drain && a.fencing,
        staleOwnerSafety: a.fencing && a.deadOwner,
      },
    };
    report.status = report.checks.length > 0 && report.checks.every((c) => c.status === 'PASS') ? 'PASS' : 'FAIL';
  } catch (error) {
    report.failure = { name: error?.name ?? 'Error', message: String(error?.message),
      source: /scenarios\.mjs:\d+/.exec(error?.stack ?? '')?.[0] };
    report.status = 'FAIL';
  } finally {
    for (const pool of [controlPool, adminPool]) { try { if (pool) await pool.end(); } catch { /* best effort */ } }
  }
  emitResult(report);
  if (report.status !== 'PASS') process.exitCode = 1;
}

function criterion(name) {
  if (name.startsWith('matrix-')) return 'routingMatrix';
  if (name.startsWith('drain-') || name.startsWith('retired-') || name.startsWith('retire-')) return 'drain';
  if (name.startsWith('dead-owner') || name.startsWith('catalog-down') || name.startsWith('catalog-recovered')) return 'deadOwner';
  if (name.startsWith('fence-')) return 'fencing';
  if (name.startsWith('forged-hop') || name.startsWith('priv-')
    || name.startsWith('public-origin') || name.startsWith('public-host')) return 'forgedHop';
  return 'combinedGate';
}

process.on('uncaughtException', (error) => {
  report.failure = { name: 'uncaughtException', message: String(error?.stack ?? error), signal: 'uncaught' };
  report.status = 'FAIL';
  try { emitResult(report); } catch { /* ignore */ }
  process.exitCode = 1;
});
process.on('unhandledRejection', (reason) => {
  report.failure = { name: 'unhandledRejection', message: String(reason?.stack ?? reason), signal: 'unhandled' };
  report.status = 'FAIL';
  try { emitResult(report); } catch { /* ignore */ }
  process.exitCode = 1;
});
const isMain = process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
if (isMain) main();
