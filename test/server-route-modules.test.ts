// Copyright 2026 Abaxx Technologies
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/**
 * Route module smoke tests — import and mount routes with inert fakes,
 * inspect the Express route table without starting a server process.
 */

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
