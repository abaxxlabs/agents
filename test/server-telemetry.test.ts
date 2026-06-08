import { describe, expect, it, vi } from 'vitest';
import {
  AuditWriteFailedError,
  CredentialInvalidError,
  QueryRejectedError,
  createJwt,
  createQueryService,
} from '#index.js';
import { AuditLogger } from '#audit/index.js';
import { createSigner, generateDidKey } from '#auth/index.js';
import { InMemoryRevocationStore } from '#storage/memory/revocation-store.js';
import { VcVerifier } from '#identity/index.js';
import { createPerSessionRateLimiter } from '../packages/server/src/rate-limit.js';
import {
  createAuditTelemetrySink,
  createOperationalTelemetry,
  createQueryTelemetrySink,
  createRateLimitTelemetrySink,
  createRevocationTelemetrySink,
  sanitizeTelemetryFields,
} from '../packages/server/src/telemetry.js';

function createRecorder() {
  const records: unknown[] = [];
  const telemetry = createOperationalTelemetry({
    instanceId: 'test-instance',
    now: () => new Date('2026-04-29T12:00:00.000Z'),
    sink: (record) => records.push(record),
  });
  return { telemetry, records };
}

function serialized(value: unknown): string {
  return JSON.stringify(value);
}

describe('server operational telemetry', () => {
  it('keeps telemetry best-effort when sanitization or the sink fails', async () => {
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    const telemetry = createOperationalTelemetry({
      sink: () => {
        throw new Error('sink unavailable');
      },
    });

    expect(() => telemetry.record('query.rejected', {
      deeply: { nested: { cyclic } },
    })).not.toThrow();
    expect(telemetry.metricsSnapshot()).toEqual(expect.arrayContaining([
      { name: 'agents_query_total', labels: { outcome: 'rejected' }, value: 1 },
    ]));

    const service = createQueryService({
      executor: {
        query: async () => {
          throw new QueryRejectedError('did:key:zAgentQuery', 'scope rejected');
        },
      },
      telemetry: createQueryTelemetrySink(telemetry),
    });

    await expect(service.execute({
      agent: 'did:key:zAgentQuery',
      credential: 'eyJ.best.effort',
      table: 'employees',
      sql: 'SELECT name FROM employees',
    })).rejects.toThrow('Query rejected');
  });

  it('keeps direct custom telemetry sinks best-effort at lower-level hooks', async () => {
    const throwingSink = () => {
      throw new Error('custom sink failed');
    };

    const limiter = createPerSessionRateLimiter();
    limiter.setTelemetrySink({ rateLimitChecked: throwingSink });
    expect(() => limiter.check('raw-session-token', 'sign', 1, 60_000)).not.toThrow();

    const queryService = createQueryService({
      executor: {
        query: async () => {
          throw new QueryRejectedError('did:key:zAgentQuery', 'scope rejected');
        },
      },
      telemetry: {
        credentialVerification: throwingSink,
        queryRejected: throwingSink,
        auditWriteFailed: throwingSink,
      },
    });
    await expect(queryService.execute({
      agent: 'did:key:zAgentQuery',
      credential: 'eyJ.direct.sink',
      table: 'employees',
      sql: 'SELECT name FROM employees',
    })).rejects.toThrow('Query rejected');

    const agent = generateDidKey();
    const human = generateDidKey();
    const auditLogger = new AuditLogger({
      auditStore: {
        append: vi.fn().mockRejectedValue(new Error('disk full')),
        loadLastRecord: vi.fn().mockResolvedValue(null),
        loadLastRecordLocked: vi.fn().mockResolvedValue(null),
        query: vi.fn().mockResolvedValue([]),
      },
      enabled: true,
    });
    auditLogger.setTelemetrySink({ auditWriteFailed: throwingSink });
    // Audit logger is fail-closed; a throwing telemetry sink must not mask the
    // AuditWriteFailedError that the failing auditStore.append produces.
    await expect(auditLogger.log({
      agentDid: agent.did,
      ownerDid: human.did,
      credentialJwt: 'eyJ.audit.direct',
      sql: 'SELECT name FROM patients',
      columnsAccessed: ['patients.name'],
      rowCount: 1,
      durationMs: 1,
    }, createSigner(agent.privateKey))).rejects.toThrow('Could not write audit record');

    const verifier = new VcVerifier({
      clockSkew: '30s',
      revocationStore: new InMemoryRevocationStore(),
    });
    verifier.registerKey(human.did, human.publicKey);
    verifier.setTelemetrySink({ revocationCheck: throwingSink });
    const credential = await createJwt({
      iss: human.did,
      sub: agent.did,
      jti: 'direct-telemetry-jti',
      exp: Math.floor(Date.now() / 1000) + 60,
      vc: {
        credentialSubject: {
          id: agent.did,
          scope: { columns: ['patients.name'], actions: ['read'] },
        },
      },
    }, human.privateKey);

    await expect(verifier.verify(credential)).resolves.toMatchObject({ valid: true });
  });

  it('hashes or redacts dangerous fields before structured logging', () => {
    const err = new Error(
      'connect ECONNREFUSED postgresql://user:secret@db.internal:5432/agents\n    at private-stack.ts:42',
    ) as Error & { code: string };
    err.code = 'DB_CONNECTION_FAILED';
    err.stack = 'Error: stack with bearer abc.def.ghi';

    const sanitized = sanitizeTelemetryFields({
      agentDid: 'did:key:zRawAgentDid',
      credential: 'eyJ.raw.credential',
      authorization: 'Bearer raw-bearer-token',
      sql: 'SELECT secret_column FROM patients WHERE id = $1',
      connectionString: 'postgresql://user:secret@db.internal:5432/agents',
      privateKey: '-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----',
      stack: 'at private-stack.ts:42',
      error: err,
    });

    const body = serialized(sanitized);

    expect(sanitized).toMatchObject({
      agentDidHash: expect.any(String),
      credentialHash: expect.any(String),
      authorization: '[redacted]',
      sqlHash: expect.any(String),
      sqlByteLength: expect.any(Number),
      connectionString: '[redacted]',
      privateKey: '[redacted]',
      errorName: 'Error',
      errorCode: 'DB_CONNECTION_FAILED',
    });
    expect(body).not.toContain('did:key:zRawAgentDid');
    expect(body).not.toContain('eyJ.raw.credential');
    expect(body).not.toContain('raw-bearer-token');
    expect(body).not.toContain('SELECT secret_column');
    expect(body).not.toContain('postgresql://');
    expect(body).not.toContain('db.internal');
    expect(body).not.toContain('BEGIN PRIVATE KEY');
    expect(body).not.toContain('private-stack');
  });

  it('records rate-limit metrics and hashes the session principal on rejected events', () => {
    const { telemetry, records } = createRecorder();
    const limiter = createPerSessionRateLimiter();
    limiter.setTelemetrySink(createRateLimitTelemetrySink(telemetry));

    expect(limiter.check('raw-session-token', 'sign', 1, 60_000).allowed).toBe(true);
    expect(limiter.check('raw-session-token', 'sign', 1, 60_000).allowed).toBe(false);

    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({
      event: 'rate_limit.rejected',
      operation: 'sign',
      principalHash: expect.any(String),
      retryAfterSeconds: expect.any(Number),
    });
    expect(serialized(records)).not.toContain('raw-session-token');
    expect(telemetry.metricsSnapshot()).toEqual(expect.arrayContaining([
      { name: 'agents_rate_limit_total', labels: { operation: 'sign', outcome: 'allowed' }, value: 1 },
      { name: 'agents_rate_limit_total', labels: { operation: 'sign', outcome: 'rejected' }, value: 1 },
    ]));
  });

  it('emits query rejection and credential verification events without raw SQL or credentials', async () => {
    const { telemetry, records } = createRecorder();
    const queryTelemetry = createQueryTelemetrySink(telemetry);
    const credential = 'eyJ.raw.query.credential';
    const sql = 'SELECT salary, ssn FROM employees';

    const rejectedService = createQueryService({
      executor: {
        query: async () => {
          throw new QueryRejectedError('did:key:zAgentQuery', `Rejected raw SQL: ${sql}`);
        },
      },
      telemetry: queryTelemetry,
    });

    await expect(rejectedService.execute({
      agent: 'did:key:zAgentQuery',
      credential,
      table: 'employees',
      sql,
    })).rejects.toThrow('Query rejected');

    const invalidService = createQueryService({
      executor: {
        query: async () => {
          throw new CredentialInvalidError('did:key:zAgentQuery', 'bad bearer token eyJ.secret');
        },
      },
      telemetry: queryTelemetry,
    });

    await expect(invalidService.execute({
      agent: 'did:key:zAgentQuery',
      credential,
      table: 'employees',
      sql,
    })).rejects.toThrow('Signature verification failed');

    expect(records.map((record) => (record as { event: string }).event)).toEqual([
      'query.rejected',
      'credential.verification_failed',
    ]);
    const body = serialized(records);
    expect(body).not.toContain('did:key:zAgentQuery');
    expect(body).not.toContain(credential);
    expect(body).not.toContain('SELECT salary');
    expect(body).not.toContain('ssn');
    expect(body).not.toContain('eyJ.secret');
  });

  it('emits audit write failure telemetry without raw storage details on fail-closed rejection', async () => {
    const { telemetry, records } = createRecorder();
    const agent = generateDidKey();
    const human = generateDidKey();
    const store = {
      append: vi.fn().mockRejectedValue(
        new Error('disk full at postgresql://user:secret@db.internal:5432/agents\n    at audit-store.ts:9'),
      ),
      loadLastRecord: vi.fn().mockResolvedValue(null),
      loadLastRecordLocked: vi.fn().mockResolvedValue(null),
      query: vi.fn().mockResolvedValue([]),
    };
    const logger = new AuditLogger({ auditStore: store, enabled: true });
    logger.setTelemetrySink(createAuditTelemetrySink(telemetry));

    await expect(logger.log({
      agentDid: agent.did,
      ownerDid: human.did,
      credentialJwt: 'eyJ.audit.credential',
      sql: 'SELECT secret FROM ledger',
      columnsAccessed: ['ledger.secret'],
      rowCount: 1,
      durationMs: 2,
    }, createSigner(agent.privateKey))).rejects.toThrow('Could not write audit record');

    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({
      event: 'audit.write_failed',
      operation: 'query',
      errorName: 'Error',
    });
    const body = serialized(records);
    expect(body).not.toContain('postgresql://');
    expect(body).not.toContain('db.internal');
    expect(body).not.toContain('audit-store.ts');
    expect(body).not.toContain('SELECT secret');
    expect(body).not.toContain('eyJ.audit.credential');
  });

  it('emits revocation check telemetry with hashed credential IDs', async () => {
    const { telemetry, records } = createRecorder();
    const human = generateDidKey();
    const agent = generateDidKey();
    const verifier = new VcVerifier({
      clockSkew: '30s',
      revocationStore: new InMemoryRevocationStore(),
    });
    verifier.registerKey(human.did, human.publicKey);
    verifier.setTelemetrySink(createRevocationTelemetrySink(telemetry));

    const credential = await createJwt({
      iss: human.did,
      sub: agent.did,
      jti: 'raw-revocation-jti',
      exp: Math.floor(Date.now() / 1000) + 60,
      vc: {
        credentialSubject: {
          id: agent.did,
          scope: { columns: ['patients.name'], actions: ['read'] },
        },
      },
    }, human.privateKey);

    const result = await verifier.verify(credential);

    expect(result.valid).toBe(true);
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({
      event: 'revocation.check_succeeded',
      source: 'local_store',
      credentialIdHash: expect.any(String),
      outcome: 'not_revoked',
    });
    expect(serialized(records)).not.toContain('raw-revocation-jti');
  });

  it('records fail-closed audit write errors from the query service without error messages', async () => {
    const { telemetry, records } = createRecorder();
    const service = createQueryService({
      executor: {
        query: async () => {
          throw new AuditWriteFailedError(
            'could not append to postgresql://user:secret@db.internal:5432/agents',
            false,
          );
        },
      },
      telemetry: createQueryTelemetrySink(telemetry),
    });

    await expect(service.execute({
      agent: 'did:key:zAuditAgent',
      credential: 'eyJ.audit.fail.closed',
      table: 'ledger',
      sql: 'SELECT secret FROM ledger',
    })).rejects.toThrow('Could not write audit record');

    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({
      event: 'audit.write_failed',
      table: 'ledger',
      errorName: 'AuditWriteFailedError',
      errorCode: 'AUDIT_WRITE_FAILED',
    });
    expect(serialized(records)).not.toContain('postgresql://');
    expect(serialized(records)).not.toContain('db.internal');
    expect(serialized(records)).not.toContain('SELECT secret');
    expect(serialized(records)).not.toContain('eyJ.audit.fail.closed');
  });
});
