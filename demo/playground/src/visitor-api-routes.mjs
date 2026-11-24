import {
  ORDER_TABLE,
  areKnownOrderColumns,
  isConfiguredMockUser,
  isValidAgentName,
  parseBody,
} from './request-policy.mjs';
import { logSafeError } from './safe-diagnostics.mjs';
import {
  DuplicateVisitorSessionCookieError,
  SessionPlaneUnavailableError,
  errorPayload,
  isDelegationRejection,
  rejected,
} from './visitor-errors.mjs';
import { allowedQueryInspection, rejectedQueryInspection } from './query-inspection.mjs';

const SIMULATOR_ROUTES = [
  'GET /api/sim/agent',
  'POST /api/sim/config',
  'POST /api/sim/raw',
  'POST /api/sim/scoped',
  'POST /api/sim/reset',
  'GET /api/sim/raw-bytes',
];
const RENEWING_SIMULATOR_ROUTES = new Set([
  'POST /api/sim/config',
  'POST /api/sim/raw',
  'POST /api/sim/scoped',
  'POST /api/sim/reset',
]);

/**
 * Build the visitor-facing route table. Session resolution and cookie policy
 * stay in the HTTP transport; this module owns the demo operations.
 */
export function createVisitorRoutes({
  registry,
  sessionStore,
  sessionCookie,
  metrics,
  requireVisitor,
  releaseSession,
  readCookie,
  markExpired,
  markLegacyExpired,
  createSandboxId,
  hashOrigin,
  requestOrigin,
  visitorCookieName,
  legacyCookieName,
  cookieSuffix,
  legacyVisitorCookie,
  libraryVersion,
  now,
}) {
  const routes = {
    'GET /api/status': async () => [200, { status: 'ok', libraryVersion }],

    'POST /api/login': async (req) => {
      const { humanDid } = parseBody(req);
      if (!isConfiguredMockUser(humanDid)) {
        return [400, { error: 'ValidationError', message: 'humanDid must be alice or bob' }];
      }

      let sandboxId;
      let runtime;
      let created = false;
      let reusedToken;
      let reusedExpiresAt;
      let token;
      try {
        token = readCookie(req, visitorCookieName);
      } catch (err) {
        // The legacy local cookie shares the modern name at a different path.
        if (!(err instanceof DuplicateVisitorSessionCookieError) || visitorCookieName !== legacyCookieName) {
          throw err;
        }
        markLegacyExpired(req);
      }
      if (token !== undefined) {
        const verdict = sessionCookie.verify(token);
        if (verdict.ok) {
          const resolution = await sessionStore.resolve({ sandboxId: verdict.sandboxId }).catch((err) => {
            throw new SessionPlaneUnavailableError('Visitor session store is unavailable', { cause: err });
          });
          if (resolution.ok && registry.hasRuntime(verdict.sandboxId)) {
            sandboxId = verdict.sandboxId;
            runtime = registry.getRuntime(sandboxId);
            reusedToken = token;
            reusedExpiresAt = verdict.expiresAt;
          } else if (!resolution.ok) {
            await releaseSession(verdict.sandboxId);
            markExpired(req);
          }
          // An active row without a local runtime may belong to another replica.
          // Keep it until it expires or the visitor completes a new login.
        } else {
          markExpired(req);
        }
      }

      if (!runtime) {
        const originHash = hashOrigin(requestOrigin(req));
        const origin = metrics?.bucketLabel('origin', originHash.slice(0, 12)) ?? originHash.slice(0, 12);
        const candidate = createSandboxId();
        const admission = await sessionStore.admit({ sandboxId: candidate, originHash }).catch((err) => {
          throw new SessionPlaneUnavailableError('Visitor session store is unavailable', { cause: err });
        });
        if (!admission.ok) {
          metrics?.counter('playground_admission_rejections_total', { origin, reason: admission.reason });
          if (admission.reason === 'rate-limit') {
            return [429, {
              error: 'RateLimitExceeded',
              message: 'New visitor session limit reached; retry later',
            }, { 'retry-after': String(Math.ceil(admission.retryAfterMs / 1000)) }];
          }
          return [503, {
            error: 'VisitorSessionCapacityError',
            message: 'Visitor session capacity has been reached',
          }];
        }
        metrics?.counter('playground_admissions_total', { origin });
        sandboxId = candidate;
        created = true;
        try {
          runtime = await registry.createRuntime(sandboxId);
        } catch (err) {
          await releaseSession(sandboxId);
          throw err;
        }
      }

      let session;
      try {
        session = await runtime.loginSession(humanDid);
      } catch (err) {
        if (created) await releaseSession(sandboxId);
        throw err;
      }
      await sessionStore.touch({ sandboxId }).catch((err) => {
        logSafeError(console, 'error', 'Visitor session activity update failed', err);
      });
      registry.touchRuntime(sandboxId);
      const reservation = await sessionStore.resolve({ sandboxId }).catch((err) => {
        throw new SessionPlaneUnavailableError('Visitor session store is unavailable', { cause: err });
      });
      if (!reservation.ok) {
        await releaseSession(sandboxId);
        return [503, {
          error: 'VisitorSessionUnavailable',
          message: 'Visitor session expired while it was being prepared; retry',
        }];
      }
      const issued = reusedToken && reusedExpiresAt === reservation.expiresAt
        ? { token: reusedToken, expiresAt: reservation.expiresAt }
        : sessionCookie.issue({ sandboxId, expiresAt: reservation.expiresAt });
      const ceiling = session.scopeCeiling;
      const remainingSeconds = Math.max(1, Math.floor((issued.expiresAt - now()) / 1000));
      return [200, {
        humanDid: session.humanDid,
        ceiling: {
          columns: ceiling.columns,
          actions: ceiling.actions,
          source: ceiling.source,
          resolvedFrom: ceiling.resolvedFrom,
          credentialMaxTtlMs: ceiling.credentialMaxTtlMs,
        },
      }, { 'set-cookie': [
        `${visitorCookieName}=${issued.token}; HttpOnly; SameSite=Lax; Path=/; ` +
          `Max-Age=${remainingSeconds}; Expires=${new Date(issued.expiresAt).toUTCString()}${cookieSuffix}`,
        legacyVisitorCookie,
      ] }];
    },

    'GET /api/agents': requireVisitor(false, async (runtime, req, url) => {
      const ownerDid = url.searchParams.get('ownerDid') ?? undefined;
      return [200, { agents: await runtime.scope.listAgents({ ownerDid }) }];
    }),

    'POST /api/agents': requireVisitor(true, async (runtime, req) => {
      const { humanDid, name } = parseBody(req);
      if (!humanDid || !isValidAgentName(name)) {
        return [400, { error: 'ValidationError', message: 'humanDid required and name must be an identifier of 1 to 64 characters' }];
      }
      const session = runtime.getSession(humanDid);
      const agent = await runtime.scope.createAgentIdentity({ name, ownerDid: session.humanDid });
      return [201, { did: agent.did, name: agent.name, ownerDid: agent.ownerDid, publicKey: Buffer.from(agent.publicKey).toString('hex') }];
    }),

    'POST /api/credentials': requireVisitor(true, async (runtime, req) => {
      const { humanDid, agent, columns, expiresIn } = parseBody(req);
      if (!humanDid || !agent || !areKnownOrderColumns(columns)) {
        return [400, { error: 'ValidationError', message: 'humanDid, agent and valid orders columns[] required' }];
      }
      const session = runtime.getSession(humanDid);
      try {
        const credential = await session.issueCredential({
          agent,
          columns,
          actions: ['read'],
          expiresIn: expiresIn ?? '1h',
        });
        return [201, { credential }];
      } catch (err) {
        return rejected(err);
      }
    }),

    'POST /api/delegate': requireVisitor(true, async (runtime, req) => {
      const { sourceAgentDid, sourceCredential, targetAgentDid, columns, expiresIn } = parseBody(req);
      if (!sourceAgentDid || !sourceCredential || !targetAgentDid || !areKnownOrderColumns(columns)) {
        return [400, { error: 'ValidationError', message: 'sourceAgentDid, sourceCredential, targetAgentDid and valid orders columns[] required' }];
      }
      try {
        const credential = await runtime.scope.delegateCredential(sourceAgentDid, sourceCredential, {
          targetAgent: targetAgentDid,
          columns,
          actions: ['read'],
          expiresIn: expiresIn ?? '15m',
        });
        return [201, { credential }];
      } catch (err) {
        if (isDelegationRejection(err)) return [403, errorPayload(err)];
        return rejected(err);
      }
    }),

    'POST /api/query': requireVisitor(true, async (runtime, req) => {
      const { agent, credential, sql, table } = parseBody(req);
      if (!agent || !credential || typeof sql !== 'string' || !sql || (table !== undefined && table !== ORDER_TABLE)) {
        return [400, { error: 'ValidationError', message: 'agent, credential and sql required; table can only be orders' }];
      }
      try {
        const result = await runtime.scope.query({ agent, credential, sql, table: ORDER_TABLE });
        return [200, { ok: true, ...result, inspection: allowedQueryInspection(agent, sql, result.metadata) }];
      } catch (err) {
        return rejected(err, { ok: false, inspection: rejectedQueryInspection(agent, sql, err) });
      }
    }),

    'GET /api/audit': requireVisitor(false, async (runtime) => {
      const records = await runtime.scope.auditLoggerInstance.export();
      return [200, { records: records.slice(-50).reverse() }];
    }),

  };

  for (const routeKey of SIMULATOR_ROUTES) {
    routes[routeKey] = requireVisitor(RENEWING_SIMULATOR_ROUTES.has(routeKey), (runtime, req, url) => {
      const handler = runtime.simulator.routes[routeKey];
      if (!handler) throw new Error(`Visitor simulator route is unavailable: ${routeKey}`);
      return handler(req, url);
    });
  }

  return routes;
}
