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

import { describe, expect, it } from 'vitest';
import type { z } from 'zod';
import { ScopeViolationError, TtlExceededError } from '../src/errors.js';
import {
  FixedWindowRateLimiter,
  JWT_MAX_CHARS,
  RequestValidationError,
  SIGN_PAYLOAD_MAX_BYTES,
  SQL_MAX_CHARS,
  assertExpiresInBound,
  assertWithinRateLimit,
  assertUtf8MaxBytes,
  normalizeDomainError,
  restValidationSchemas,
  toHttpErrorBody,
  toMcpErrorBody,
  validateRequest,
} from '../src/transport/index.js';

describe('transport boundary validation schemas', () => {
  const schemaCases: Array<{
    name: string;
    schema: z.ZodTypeAny;
    valid: Record<string, unknown>;
    missing?: Record<string, unknown>;
    malformed?: Record<string, unknown>;
    oversized?: Record<string, unknown>;
  }> = [
    {
      name: 'authSessionBody',
      schema: restValidationSchemas.authSessionBody,
      valid: { mockHumanDid: 'Dr. Chen' },
      malformed: { mockHumanDid: 42 },
      oversized: { mockHumanDid: 'x'.repeat(513) },
    },
    {
      name: 'createAgentBody',
      schema: restValidationSchemas.createAgentBody,
      valid: { name: 'agent-a' },
      missing: {},
      malformed: { name: 42 },
      oversized: { name: 'x'.repeat(129) },
    },
    {
      name: 'listAgentsQuery',
      schema: restValidationSchemas.listAgentsQuery,
      valid: { limit: '10' },
      malformed: { limit: 'abc' },
      oversized: { limit: '101' },
    },
    {
      name: 'issueCredentialBody',
      schema: restValidationSchemas.issueCredentialBody,
      valid: {
        agent: 'did:key:agent',
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '4h',
      },
      missing: {
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '4h',
      },
      malformed: {
        agent: 'did:key:agent',
        columns: ['patients.name'],
        actions: ['write'],
        expiresIn: '4h',
      },
      oversized: {
        agent: 'did:key:agent',
        columns: Array.from({ length: 101 }, (_, index) => `patients.c${index}`),
        actions: ['read'],
        expiresIn: '4h',
      },
    },
    {
      name: 'delegateCredentialBody',
      schema: restValidationSchemas.delegateCredentialBody,
      valid: {
        sourceCredential: 'header.payload.sig',
        targetAgent: 'did:key:worker',
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '1h',
      },
      missing: {
        targetAgent: 'did:key:worker',
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '1h',
      },
      malformed: {
        sourceCredential: 'header.payload.sig',
        targetAgent: 'did:key:worker',
        columns: ['patients.name'],
        actions: ['write'],
        expiresIn: '1h',
      },
      oversized: {
        sourceCredential: 'x'.repeat(JWT_MAX_CHARS + 1),
        targetAgent: 'did:key:worker',
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '1h',
      },
    },
    {
      name: 'listCredentialsQuery',
      schema: restValidationSchemas.listCredentialsQuery,
      valid: { issuedAfter: '2026-04-29T00:00:00Z' },
      malformed: { issuedAfter: 'not-a-date' },
      oversized: { limit: '501' },
    },
    {
      name: 'queryBody',
      schema: restValidationSchemas.queryBody,
      valid: {
        agent: 'did:key:agent',
        credential: 'header.payload.sig',
        table: 'patients',
        sql: 'SELECT name FROM patients',
      },
      missing: {
        credential: 'header.payload.sig',
        table: 'patients',
        sql: 'SELECT name FROM patients',
      },
      malformed: {
        agent: 'did:key:agent',
        credential: 'header.payload.sig',
        table: 'patients; DROP TABLE patients',
        sql: 'SELECT name FROM patients',
      },
      oversized: {
        agent: 'did:key:agent',
        credential: 'header.payload.sig',
        table: 'patients',
        sql: 'x'.repeat(SQL_MAX_CHARS + 1),
      },
    },
    {
      name: 'auditQuery',
      schema: restValidationSchemas.auditQuery,
      valid: { limit: '25' },
      malformed: { limit: 'abc' },
      oversized: { limit: '501' },
    },
    {
      name: 'verifyAuditBody',
      schema: restValidationSchemas.verifyAuditBody,
      valid: { auditId: 'audit-1' },
      missing: {},
      malformed: { auditId: 42 },
      oversized: { auditId: 'x'.repeat(513) },
    },
    {
      name: 'verifyChainBody',
      schema: restValidationSchemas.verifyChainBody,
      valid: { limit: 100 },
      malformed: { limit: '100' },
      oversized: { limit: 1001 },
    },
    {
      name: 'signBody',
      schema: restValidationSchemas.signBody,
      valid: { payload: 'hello' },
      missing: {},
      malformed: { payload: 42 },
      oversized: { payload: 'x'.repeat(SIGN_PAYLOAD_MAX_BYTES + 1) },
    },
    {
      name: 'challengeBody',
      schema: restValidationSchemas.challengeBody,
      valid: { requestorDid: 'did:key:agent', ttlSeconds: 60 },
      malformed: { ttlSeconds: '60' },
      oversized: { ttlSeconds: 301 },
    },
    {
      name: 'mcpSseQuery',
      schema: restValidationSchemas.mcpSseQuery,
      valid: { 'x-session': 'session-1' },
      missing: {},
      malformed: { 'x-session': 42 },
      oversized: { 'x-session': 'x'.repeat(2049) },
    },
    {
      name: 'mcpMessagesQuery',
      schema: restValidationSchemas.mcpMessagesQuery,
      valid: { sessionId: 'mcp-session-1' },
      missing: {},
      malformed: { sessionId: 42 },
      oversized: { sessionId: 'x'.repeat(513) },
    },
    {
      name: 'emptyBody',
      schema: restValidationSchemas.emptyBody,
      valid: {},
    },
    {
      name: 'emptyQuery',
      schema: restValidationSchemas.emptyQuery,
      valid: {},
    },
  ];

  it('rejects unexpected fields for every public REST body/query schema', () => {
    for (const { name, schema, valid } of schemaCases) {
      expect(() => validateRequest(schema, { ...valid, unexpected: true }), name).toThrow(
        RequestValidationError,
      );
    }
  });

  it('rejects missing, malformed, and oversized public inputs where applicable', () => {
    for (const { name, schema, missing, malformed, oversized } of schemaCases) {
      if (missing) {
        expect(() => validateRequest(schema, missing), `${name} missing`).toThrow(
          RequestValidationError,
        );
      }
      if (malformed) {
        expect(() => validateRequest(schema, malformed), `${name} malformed`).toThrow(
          RequestValidationError,
        );
      }
      if (oversized) {
        expect(() => validateRequest(schema, oversized), `${name} oversized`).toThrow(
          RequestValidationError,
        );
      }
    }
  });

  it('rejects required-field omissions with safe issue metadata', () => {
    expect(() => validateRequest(restValidationSchemas.createAgentBody, {})).toThrow(
      RequestValidationError,
    );

    try {
      validateRequest(restValidationSchemas.queryBody, {
        table: 'patients',
        sql: 'SELECT name FROM patients',
      });
    } catch (err) {
      const normalized = normalizeDomainError(err);
      expect(normalized).toMatchObject({
        code: 'VALIDATION_FAILED',
        httpStatus: 400,
      });
      expect(JSON.stringify(normalized.details)).toContain('agent');
      expect(JSON.stringify(normalized.details)).not.toContain('SELECT name');
    }
  });

  it('rejects malformed and oversized public inputs', () => {
    expect(() => validateRequest(restValidationSchemas.listAgentsQuery, { limit: 'abc' })).toThrow(
      RequestValidationError,
    );
    expect(() =>
      validateRequest(restValidationSchemas.issueCredentialBody, {
        agent: 'did:key:agent',
        columns: [],
        actions: ['read'],
        expiresIn: '4h',
      }),
    ).toThrow(RequestValidationError);
    expect(() =>
      validateRequest(restValidationSchemas.issueCredentialBody, {
        agent: 'did:key:agent',
        columns: ['patients.name'],
        actions: ['write'],
        expiresIn: '4h',
      }),
    ).toThrow(RequestValidationError);
    expect(() =>
      validateRequest(restValidationSchemas.queryBody, {
        agent: 'did:key:agent',
        credential: 'header.payload.sig',
        table: 'patients; DROP TABLE patients',
        sql: 'SELECT name FROM patients',
      }),
    ).toThrow(RequestValidationError);
    expect(() => validateRequest(restValidationSchemas.challengeBody, { ttlSeconds: 301 })).toThrow(
      RequestValidationError,
    );
    expect(() => assertUtf8MaxBytes('payload', 'x'.repeat(65 * 1024), 64 * 1024)).toThrow(
      RequestValidationError,
    );
  });

  it('applies explicit bounded defaults for public query parameters', () => {
    expect(validateRequest(restValidationSchemas.listAgentsQuery, {})).toEqual({ limit: 100 });
    expect(validateRequest(restValidationSchemas.listCredentialsQuery, {})).toEqual({ limit: 100 });
    expect(validateRequest(restValidationSchemas.auditQuery, {})).toEqual({ limit: 50 });
    expect(validateRequest(restValidationSchemas.verifyChainBody, {})).toEqual({ limit: 1000 });
  });
});

describe('transport boundary error normalization', () => {
  it('renders REST and MCP scope violations with the same classification and no column oracle', () => {
    const err = new ScopeViolationError('did:key:agent', ['patients.ssn'], ['patients.name']);

    const normalized = normalizeDomainError(err);
    const http = toHttpErrorBody(normalized);
    const mcp = toMcpErrorBody(normalized);

    expect(http).toMatchObject({ error: 'SCOPE_VIOLATION', code: 'SCOPE_VIOLATION' });
    expect(mcp).toMatchObject({ error: 'SCOPE_VIOLATION' });
    expect(JSON.stringify(http)).not.toContain('ssn');
    expect(JSON.stringify(mcp)).not.toContain('patients.name');
  });

  it('does not expose internal diagnostics from unknown errors', () => {
    const err = new Error(
      'connect ECONNREFUSED postgresql://user:secret@db.internal:5432/app at /srv/private/file.ts:12',
    );

    const body = toHttpErrorBody(normalizeDomainError(err));

    expect(body).toEqual({
      error: 'INTERNAL_ERROR',
      code: 'INTERNAL_ERROR',
      message: 'An internal error occurred.',
    });
    expect(JSON.stringify(body)).not.toContain('secret');
    expect(JSON.stringify(body)).not.toContain('/srv/private');
  });
});

describe('shared rate limiter', () => {
  it('keys limits by the same principal and operation across transports', () => {
    const limiter = new FixedWindowRateLimiter();

    expect(
      assertWithinRateLimit(limiter, {
        principal: 'session-1',
        operation: 'sign',
        limit: 2,
        windowMs: 60_000,
      }).allowed,
    ).toBe(true);

    expect(
      assertWithinRateLimit(limiter, {
        principal: 'session-1',
        operation: 'sign',
        limit: 2,
        windowMs: 60_000,
      }).allowed,
    ).toBe(true);

    expect(() =>
      assertWithinRateLimit(limiter, {
        principal: 'session-1',
        operation: 'sign',
        limit: 2,
        windowMs: 60_000,
      }),
    ).toThrow('Sign rate limit exceeded');

    expect(
      assertWithinRateLimit(limiter, {
        principal: 'session-1',
        operation: 'challenge',
        limit: 2,
        windowMs: 60_000,
      }).allowed,
    ).toBe(true);
  });
});

describe('expiresIn validation', () => {
  const MAX_TTL_24H = 24 * 60 * 60 * 1000; // 86_400_000ms

  describe('schema rejects malformed duration strings', () => {
    const invalidDurations = ['invalid', '90', '5w', 'abc123', '-1h', '', '1m1m'];
    for (const bad of invalidDurations) {
      it(`rejects "${bad}"`, () => {
        expect(() =>
          validateRequest(restValidationSchemas.issueCredentialBody, {
            agent: 'did:key:agent',
            columns: ['patients.name'],
            actions: ['read'],
            expiresIn: bad,
          }),
        ).toThrow(RequestValidationError);
      });
    }
  });

  describe('schema accepts valid duration strings', () => {
    const validDurations = ['4h', '1d', '30m', '1m30s', '500ms', '1.5h'];
    for (const good of validDurations) {
      it(`accepts "${good}"`, () => {
        expect(() =>
          validateRequest(restValidationSchemas.issueCredentialBody, {
            agent: 'did:key:agent',
            columns: ['patients.name'],
            actions: ['read'],
            expiresIn: good,
          }),
        ).not.toThrow();
      });
    }
  });

  describe('schema accepts valid integer seconds', () => {
    it('accepts 3600', () => {
      expect(() =>
        validateRequest(restValidationSchemas.issueCredentialBody, {
          agent: 'did:key:agent',
          columns: ['patients.name'],
          actions: ['read'],
          expiresIn: 3600,
        }),
      ).not.toThrow();
    });
  });

  describe('schema rejects invalid integer values', () => {
    it('rejects 0', () => {
      expect(() =>
        validateRequest(restValidationSchemas.issueCredentialBody, {
          agent: 'did:key:agent',
          columns: ['patients.name'],
          actions: ['read'],
          expiresIn: 0,
        }),
      ).toThrow(RequestValidationError);
    });

    it('rejects negative', () => {
      expect(() =>
        validateRequest(restValidationSchemas.issueCredentialBody, {
          agent: 'did:key:agent',
          columns: ['patients.name'],
          actions: ['read'],
          expiresIn: -3600,
        }),
      ).toThrow(RequestValidationError);
    });
  });

  describe('assertExpiresInBound', () => {
    it('passes when string duration is within bound', () => {
      expect(() => assertExpiresInBound('4h', MAX_TTL_24H)).not.toThrow();
    });

    it('passes when integer seconds are within bound', () => {
      expect(() => assertExpiresInBound(3600, MAX_TTL_24H)).not.toThrow();
    });

    it('passes at exactly the bound', () => {
      expect(() => assertExpiresInBound('24h', MAX_TTL_24H)).not.toThrow();
      expect(() => assertExpiresInBound(86400, MAX_TTL_24H)).not.toThrow();
    });

    it('rejects string duration exceeding bound', () => {
      expect(() => assertExpiresInBound('48h', MAX_TTL_24H)).toThrow(TtlExceededError);
    });

    it('rejects integer seconds exceeding bound', () => {
      expect(() => assertExpiresInBound(86401, MAX_TTL_24H)).toThrow(TtlExceededError);
    });

    it('error message names the violated bound', () => {
      try {
        assertExpiresInBound('48h', MAX_TTL_24H);
        expect.unreachable('should have thrown');
      } catch (err) {
        expect(err).toBeInstanceOf(TtlExceededError);
        const te = err as TtlExceededError;
        expect(te.code).toBe('TTL_EXCEEDED');
        expect(te.message).toContain('86400');
      }
    });

    it('maps to HTTP 400 via normalizeDomainError', () => {
      try {
        assertExpiresInBound('48h', MAX_TTL_24H);
        expect.unreachable('should have thrown');
      } catch (err) {
        const normalized = normalizeDomainError(err);
        expect(normalized.httpStatus).toBe(400);
        expect(normalized.code).toBe('TTL_EXCEEDED');
      }
    });

    it('delegate-credential schema also rejects malformed strings', () => {
      expect(() =>
        validateRequest(restValidationSchemas.delegateCredentialBody, {
          sourceCredential: 'header.payload.sig',
          targetAgent: 'did:key:worker',
          columns: ['patients.name'],
          actions: ['read'],
          expiresIn: 'not-a-duration',
        }),
      ).toThrow(RequestValidationError);
    });
  });
});
