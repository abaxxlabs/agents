// Bounded owner-aware router for the two-worker routing/fencing proof.
//
// The catalog is the single source of truth for owner + generation. Every
// session operation is resolved against it. The public surface strips all
// X-Proof-* headers so an untrusted browser cannot select an owner or forge a
// hop. The internal surface requires an HMAC over the routing payload (path,
// token hash, owner, generation, deadline, nonce), bounded by a hop limit (1)
// and a deadline window, and re-resolves the destination from the catalog so a
// forged or stale header cannot win. The control surface (drain/retire/sweep)
// uses a separate shared control HMAC.

import { createHmac, timingSafeEqual, randomBytes } from 'node:crypto';
import { tokenHash } from './catalog.mjs';

export const PROOF_HEADERS = ['x-proof-token-hash', 'x-proof-owner', 'x-proof-generation',
  'x-proof-signature', 'x-proof-deadline', 'x-proof-nonce', 'x-proof-hop'];

const CONTROL_ACTIONS = new Set(['drain', 'retire', 'dump']);
export const HOP_WINDOW_MS = 15_000;
// Maximum internal hops a forwarded operation may have taken.
export const MAX_HOP = 1;


function timingSafeHexEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length || a.length === 0) return false;
  return timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
}

export function signRouting(payload, secret) {
  return createHmac('sha256', Buffer.from(secret, 'hex')).update(payload).digest('hex');
}

// Deterministic routing payload: every field that identifies the hop.
export function routingPayload({ path, tokenHash, owner, generation, deadline, nonce }) {
  return [path, tokenHash, owner, String(generation), String(deadline), nonce].join('|');
}

export function controlPayload({ action, workerId, deadline, nonce }) {
  return ['control', action, workerId, String(deadline), nonce].join('|');
}

export function classifyRoute(path) {
  if (path === '/' || path === '/healthz' || path === '/readyz') return { kind: 'static', path };
  if (path === '/proof/session') return { kind: 'session-create' };
  if (path === '/control') return { kind: 'control' };
  const internal = /^\/internal\/([0-9a-f]{8,64})\/([a-z0-9-]+)$/.exec(path);
  if (internal) return { kind: 'internal-op', tokenHash: internal[1], operation: internal[2] };
  const publicOp = /^\/proof\/session\/([0-9a-f]{8,64})\/([a-z0-9-]+)$/.exec(path);
  if (publicOp) return { kind: 'public-op', tokenHash: publicOp[1], operation: publicOp[2] };
  return { kind: 'unknown' };
}

function json(status, body) {
  return { status, body };
}

/**
 * @param {object} deps
 * @param {string} deps.workerId
 * @param {Record<string,string>} deps.routingSecrets peer workerId -> hex secret (includes self)
 * @param {string} deps.controlSecret hex control HMAC secret (shared by all workers)
 * @param {object} deps.catalog createCatalog() client
 * @param {(tokenHash:string, operation:string, body?:any) => Promise<{status?:number, body?:any}>} deps.localExecute re-resolves ownership from the catalog
 * @param {(tokenHash:string, sandboxId:string) => Promise<{marker:string, owner:string, generation:number, sandboxId:string}>} deps.reserve
 * @param {(tokenHash:string, ownership:{sandboxId:string, owner:string, generation:number}) => void} deps.establishBelief
 *   called on successful reservation; the worker's in-memory belief is fixed at
 *   creation-time generation, so a later bump makes it stale
 * @param {(token:string) => Promise<void>} [deps.onSessionEstablished]
 *   awaited after the belief is established so the create response can carry
 *   the materialized runtime identity (DID persisted by the worker)
 * @param {() => Promise<{state:string}>} deps.workerState
 * @param {(action:string) => Promise<void>} deps.controlAction
 * @param {(workerId:string) => string} deps.ownerEndpoint resolve a worker's internal base URL
 * @param {(entry:object) => void} deps.trace
 * @param {(token:string) => void} [deps.evictSession] drop an in-memory session on observed loss/transfer
 * @param {string} deps.expectedHost the Host header a public request must carry (workerId:port)
 * @param {string[]} deps.allowedOrigins allowed browser Origin values (empty = any)
 */
export function createRouter({ workerId, routingSecrets, controlSecret, catalog,
  localExecute, reserve, establishBelief, onSessionEstablished, workerState, controlAction,
  ownerEndpoint, trace, evictSession, expectedHost, allowedOrigins }) {

  const emit = (entry) => trace({ worker: workerId, ...entry });

  // Admit a brand-new session only while the worker is active. A draining
  // worker keeps serving the sessions it already owns (its SDK state lives
  // here) but must not take on new ones; a retired worker takes nothing.
  // This is the readiness-vs-admission separation the ticket calls out.
  // Fast-path only: the AUTHORITATIVE gate is the in-transaction worker-row
  // lock inside proof_ctrl.reserve_session (F5), which makes a concurrent
  // drain transition impossible to slip past.
  async function admitNewSessions() {
    const state = await workerState();
    return state?.state === 'active';
  }

  // Validate an internal hop. Re-resolves ownership from the catalog; the header
  // owner/generation must match, or the hop is stale. Returns ownership or an error.
  async function checkInternalHop(requestUrl, headers) {
    const tokenHash = headers['x-proof-token-hash'];
    const owner = headers['x-proof-owner'];
    const generation = headers['x-proof-generation'];
    const signature = headers['x-proof-signature'];
    const deadline = headers['x-proof-deadline'];
    const nonce = headers['x-proof-nonce'];
    const hop = headers['x-proof-hop'];

    if (!tokenHash || !owner || !generation || !signature || !deadline || !nonce || !hop) {
      emit({ stage: 'internal', outcome: 'reject', reason: 'missing-headers' });
      return json(401, { error: 'missing-hop-headers' });
    }
    const hopCount = Number(hop);
    if (!Number.isInteger(hopCount) || hopCount < 1 || hopCount > MAX_HOP) {
      emit({ stage: 'internal', outcome: 'reject', reason: 'hop-limit' });
      return json(401, { error: 'hop-limit' });
    }
    const deadlineMs = Number(deadline);
    if (!Number.isFinite(deadlineMs) || Math.abs(Date.now() - deadlineMs) > HOP_WINDOW_MS) {
      emit({ stage: 'internal', outcome: 'reject', reason: 'deadline' });
      return json(401, { error: 'hop-deadline' });
    }
    if (owner !== workerId) {
      // A hop addressed to another worker must never be executed here.
      emit({ stage: 'internal', outcome: 'reject', reason: 'wrong-destination', owner });
      return json(401, { error: 'wrong-destination' });
    }
    // Authenticate before touching the catalog, so a forged hop cannot probe
    // whether a token is live/lost or what generation it expects (mirrors
    // handleControl: signature first, zero DB access).
    const expected = signRouting(routingPayload({ path: requestUrl, tokenHash, owner,
      generation, deadline: String(deadlineMs), nonce }), routingSecrets[workerId]);
    if (!timingSafeHexEqual(signature, expected)) {
      emit({ stage: 'internal', outcome: 'reject', reason: 'bad-signature' });
      return json(401, { error: 'signature' });
    }
    const session = await catalog.resolve(tokenHash);
    if (!session) {
      emit({ stage: 'internal', outcome: 'reject', reason: 'session-lost' });
      evictSession?.(tokenHash);
      return json(410, { error: 'session-lost', detail: 'start-a-new-session' });
    }
    if (session.owner !== owner || Number(session.generation) !== Number(generation)) {
      emit({ stage: 'internal', outcome: 'reject', reason: 'stale-hop' });
      // An owner change (transfer) away from this worker is a terminal
      // observation: the in-memory runtime can no longer serve the session.
      // A generation-only mismatch is not an eviction: this worker still
      // owns the session and its stale belief is exactly what the fence
      // contract tests.
      if (session.owner !== owner) evictSession?.(tokenHash);
      return json(409, { error: 'stale-hop' });
    }
    emit({ stage: 'internal', outcome: 'accept', hop: hopCount, owner,
      generation: Number(session.generation) });
    return { ownership: { owner: session.owner, generation: Number(session.generation) } };
  }

  async function handleInternal(url, headers, body) {
    const route = classifyRoute(url);
    if (route.kind !== 'internal-op') return json(404, { error: 'not-found' });
    const result = await checkInternalHop(url, headers);
    if ('status' in result) return result;
    const outcome = await localExecute(route.tokenHash, route.operation, body);
    return { status: outcome.status ?? 200, body: outcome.body ?? { ok: true } };
  }

  async function forwardToOwner(session, route, method, body) {
    const owner = session.owner;
    const endpoint = ownerEndpoint(owner);
    if (!endpoint) {
      emit({ stage: 'public', route: route.operation, outcome: 'no-owner-endpoint', owner });
      return json(502, { error: 'owner-endpoint-unavailable' });
    }
    const path = `/internal/${route.tokenHash}/${route.operation}`;
    const nonce = randomBytes(8).toString('hex');
    const deadline = String(Date.now() + HOP_WINDOW_MS);
    const signature = signRouting(routingPayload({ path, tokenHash: route.tokenHash, owner,
      generation: Number(session.generation), deadline, nonce }), routingSecrets[owner]);
    try {
      const response = await fetch(`${endpoint}${path}`, {
        method,
        signal: AbortSignal.timeout(HOP_WINDOW_MS),
        headers: {
          ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
          'x-proof-token-hash': route.tokenHash,
          'x-proof-owner': owner,
          'x-proof-generation': String(session.generation),
          'x-proof-signature': signature,
          'x-proof-deadline': deadline,
          'x-proof-nonce': nonce,
          'x-proof-hop': '1',
        },
        body: body !== undefined ? JSON.stringify(body) : undefined,
      });
      const payload = await response.json().catch(() => ({ error: 'bad-owner-response' }));
      emit({ stage: 'public', route: route.operation, outcome: 'forwarded', owner, status: response.status });
      return { status: response.status, body: payload };
    } catch {
      emit({ stage: 'public', route: route.operation, outcome: 'owner-unreachable', owner });
      return json(503, { error: 'dependency-unavailable', detail: owner });
    }
  }

  async function handlePublic(url, searchParams, headers, method, body) {
    // W2 boundary: the public surface is the trust edge. Browser requests
    // must carry an allowed Origin, and every request must address this
    // worker by name (workerId:port), so a misdirected or foreign request
    // is rejected before any route classification or catalog access.
    const origin = headers.origin;
    if (origin !== undefined && !allowedOrigins.includes(origin)) {
      emit({ stage: 'public', route: url, outcome: 'reject', reason: 'origin-not-allowed', origin });
      return json(403, { error: 'origin-not-allowed' });
    }
    if (headers.host !== expectedHost) {
      emit({ stage: 'public', route: url, outcome: 'reject', reason: 'host-not-allowed', host: headers.host });
      return json(403, { error: 'host-not-allowed' });
    }

    const route = classifyRoute(url);
    if (route.kind === 'static') {
      emit({ stage: 'public', route, outcome: 'static' });
      return json(200, { ok: true, endpoint: route.path, worker: workerId });
    }
    if (route.kind === 'unknown') return json(404, { error: 'not-found' });

    if (route.kind === 'session-create') {
      let canAdmit;
      try {
        canAdmit = await admitNewSessions();
      } catch (error) {
        emit({ stage: 'public', route, outcome: 'catalog-unavailable', code: error?.code ?? null });
        return json(503, { error: 'dependency-unavailable', detail: error?.code ?? 'catalog' });
      }
      if (!canAdmit) {
        emit({ stage: 'public', route, outcome: 'admission-denied' });
        return json(503, { error: 'not-accepting-sessions' });
      }
      // The opaque cookie handed to the client IS the sha256 token hash, so
      // every later resolve (public URL, internal hop header, local execute)
      const token = tokenHash(randomBytes(24).toString('hex'));
      const sandboxId = searchParams.get('sandbox') ?? '11111111-1111-4111-8111-111111111111';
      let reservation;
      try {
        reservation = await reserve(token, sandboxId);
      } catch (error) {
        // Catalog (postgres) unreachable: fail closed, never a generic 500.
        emit({ stage: 'public', route, outcome: 'catalog-unavailable', code: error?.code ?? null });
        return json(503, { error: 'dependency-unavailable', detail: error?.code ?? 'catalog' });
      }
      // F5: the in-transaction admission gate is authoritative. The
      // fast-path above can be stale (a drain landed after it), so a
      // draining/retired/unknown worker marker still refuses with the same
      // defined 503, and no session row is ever written.
      if (reservation.marker === 'admission-denied' || reservation.marker === 'unknown-worker') {
        emit({ stage: 'public', route, outcome: 'admission-denied', marker: reservation.marker });
        return json(503, { error: 'not-accepting-sessions', marker: reservation.marker });
      }
      if (reservation.marker === 'existing') {
        emit({ stage: 'public', route, outcome: 'duplicate' });
        return json(409, { error: 'session-exists' });
      }
      if (reservation.marker === 'stale') {
        emit({ stage: 'public', route, outcome: 'stale-cookie' });
        return json(410, { error: 'session-lost', detail: 'start-a-new-session' });
      }
      // The belief is fixed at creation-time generation: a later generation
      // bump (retire-stale-owner / transfer) makes this worker's cached
      // owner+generation stale, and the next mutation fences at the transaction
      // boundary. Materialization is awaited so the response carries the
      // worker's runtime identity (the DID persisted to the catalog).
      let runtimeDid = null;
      if (reservation.marker === 'created') {
        establishBelief(token, { sandboxId: reservation.sandboxId, owner: reservation.owner, generation: reservation.generation });
        if (onSessionEstablished) {
          try {
            runtimeDid = await onSessionEstablished(token);
          } catch (error) {
            emit({ stage: 'public', route, outcome: 'materialization-failed', code: error?.code ?? null });
            return json(503, { error: 'dependency-unavailable', detail: 'runtime-materialization' });
          }
        }
      }
      emit({ stage: 'public', route, outcome: 'reserved', owner: workerId, generation: reservation.generation });
      return json(200, { token, sandboxId, owner: workerId, generation: reservation.generation, runtimeDid });
    }

    if (route.kind === 'public-op') {
      let session;
      try {
        session = await catalog.resolve(route.tokenHash);
      } catch (error) {
        // Catalog (postgres) unreachable: fail closed with a defined
        // dependency-unavailable. Never a silent reroute, never a mutation.
        emit({ stage: 'public', route: route.operation, outcome: 'catalog-unavailable', code: error?.code ?? null });
        return json(503, { error: 'dependency-unavailable', detail: error?.code ?? 'catalog' });
      }
      if (!session) {
        emit({ stage: 'public', route: route.operation, outcome: 'session-lost' });
        evictSession?.(route.tokenHash);
        return json(410, { error: 'session-lost', detail: 'start-a-new-session' });
      }
      if (session.owner === workerId) {
        const outcome = await localExecute(route.tokenHash, route.operation, body);
        emit({ stage: 'public', route: route.operation, outcome: 'local' });
        return { status: outcome.status ?? 200, body: outcome.body ?? { ok: true } };
      }
      return forwardToOwner(session, route, method, body);
    }
    return json(404, { error: 'not-found' });
  }

  async function handleControl(headers) {
    const action = headers['x-proof-action'];
    const signature = headers['x-proof-signature'];
    const deadline = headers['x-proof-deadline'];
    const nonce = headers['x-proof-nonce'];
    if (!CONTROL_ACTIONS.has(action) || !signature || !deadline || !nonce) {
      emit({ stage: 'control', outcome: 'reject', reason: 'missing' });
      return json(401, { error: 'missing-control-headers' });
    }
    const deadlineMs = Number(deadline);
    if (!Number.isFinite(deadlineMs) || Math.abs(Date.now() - deadlineMs) > HOP_WINDOW_MS) {
      emit({ stage: 'control', outcome: 'reject', reason: 'deadline' });
      return json(401, { error: 'control-deadline' });
    }
    const expected = signRouting(controlPayload({ action, workerId,
      deadline: String(deadlineMs), nonce }), controlSecret);
    if (!timingSafeHexEqual(signature, expected)) {
      emit({ stage: 'control', outcome: 'reject', reason: 'bad-signature' });
      return json(401, { error: 'control-signature' });
    }
    const payload = await controlAction(action);
    emit({ stage: 'control', outcome: 'applied', action });
    return json(200, payload ?? { ok: true, action });
  }

  return { handlePublic, handleInternal, handleControl, classifyRoute };
}
