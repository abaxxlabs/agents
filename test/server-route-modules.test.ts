import { describe, expect, it } from 'vitest';
import { createServerApp } from '../packages/server/src/app.js';
import { loadServerConfig } from '../packages/server/src/config.js';
import { createOidcServices } from '../packages/server/src/oidc.js';
import { createPerSessionRateLimiter } from '../packages/server/src/rate-limit.js';
import { mountRestRoutes } from '../packages/server/src/routes.js';
import { createSessionManager } from '../packages/server/src/session.js';

type ExpressRouteLayer = { route?: { path: string } };
type ExpressRouteStack = { stack: ExpressRouteLayer[] };
type ExpressRouteInspectable = {
  _router?: ExpressRouteStack;
  router?: ExpressRouteStack;
};

function mountedRoutePaths(app: ExpressRouteInspectable): string[] {
  const stack = app._router?.stack ?? app.router?.stack ?? [];
  return stack.filter((layer) => layer.route).map((layer) => layer.route!.path);
}

describe('server route modules', () => {
  it('mounts representative REST, docs, identity, and health routes without booting the server', () => {
    const config = loadServerConfig({ NODE_ENV: 'test' });
    const app = createServerApp(config);
    const fakeScope = {
      verifierDid: 'did:key:zTestServer',
      getServerStatus: async () => ({
        agentCount: 0,
        auditRecordCount: 0,
        encryptedColumns: [],
        inMemoryAgents: 0,
        scopeMode: 'projection' as const,
      }),
    } as unknown as Parameters<typeof mountRestRoutes>[1]['scope'];
    const sessionManager = createSessionManager({
      config,
      scopeProvider: () => fakeScope,
    });

    mountRestRoutes(app, {
      config,
      scope: fakeScope,
      sessionManager,
      oidc: createOidcServices(config),
      rateLimiter: createPerSessionRateLimiter(),
      getReadinessChecks: () => [],
    });

    expect(mountedRoutePaths(app)).toEqual(
      expect.arrayContaining([
        '/openapi.json',
        '/docs',
        '/auth/session',
        '/agents',
        '/credentials',
        '/query',
        '/audit',
        '/whoami',
        '/discover',
        '/livez',
        '/readyz',
        '/health',
      ]),
    );
  });
});
