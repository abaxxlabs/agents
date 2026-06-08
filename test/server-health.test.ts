import { describe, expect, it } from 'vitest';
import {
  createLivenessResponse,
  evaluateReadiness,
  type ReadinessCheck,
} from '../packages/server/src/health.js';

describe('server health checks', () => {
  it('reports process liveness without invoking readiness dependencies', () => {
    expect(createLivenessResponse()).toEqual({ status: 'live' });
  });

  it('reports ready when migration and storage checks pass', async () => {
    const calls: string[] = [];
    const checks: ReadinessCheck[] = [
      {
        dependency: 'migration',
        check: () => {
          calls.push('migration');
        },
      },
      {
        dependency: 'storage',
        check: async () => {
          calls.push('storage');
        },
      },
    ];

    const result = await evaluateReadiness(checks);

    expect(result.httpStatus).toBe(200);
    expect(result.body).toEqual({
      status: 'ready',
      checks: [
        { dependency: 'migration', status: 'ok' },
        { dependency: 'storage', status: 'ok' },
      ],
      failedDependencies: [],
    });
    expect(calls).toEqual(['migration', 'storage']);
  });

  it('reports storage not ready by class without leaking raw failure details', async () => {
    const checks: ReadinessCheck[] = [
      { dependency: 'migration', check: () => undefined },
      {
        dependency: 'storage',
        check: () => {
          throw new Error(
            'connect ECONNREFUSED postgresql://user:secret@db.internal.example:5432/agents\n    at private-stack.ts:42',
          );
        },
      },
    ];

    const result = await evaluateReadiness(checks);
    const serialized = JSON.stringify(result.body);

    expect(result.httpStatus).toBe(503);
    expect(result.body).toEqual({
      status: 'not_ready',
      checks: [
        { dependency: 'migration', status: 'ok' },
        { dependency: 'storage', status: 'error' },
      ],
      failedDependencies: ['storage'],
    });
    expect(serialized).not.toContain('postgresql://');
    expect(serialized).not.toContain('secret');
    expect(serialized).not.toContain('db.internal');
    expect(serialized).not.toContain('private-stack');
  });

  it('reports migration not ready by class without hiding process liveness', async () => {
    const result = await evaluateReadiness([
      {
        dependency: 'migration',
        check: () => {
          throw new Error(
            'migration 008 failed: relation agents_sessions contains private schema detail',
          );
        },
      },
      { dependency: 'storage', check: () => undefined },
    ]);

    expect(result.httpStatus).toBe(503);
    expect(result.body.failedDependencies).toEqual(['migration']);
    expect(result.body.checks).toEqual([
      { dependency: 'migration', status: 'error' },
      { dependency: 'storage', status: 'ok' },
    ]);
    expect(JSON.stringify(result.body)).not.toContain('relation agents_sessions');
    expect(createLivenessResponse()).toEqual({ status: 'live' });
  });
});
