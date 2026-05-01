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
 * Transport-neutral error rendering for REST and MCP.
 *
 * Normalizes domain errors to a shared shape so REST and MCP responses stay
 * consistent. Strips internal details (stack traces, connection strings, column
 * names) before sending to untrusted clients.
 */

import { AgentScopeError, ScopeViolationError } from '../errors.js';
import { ScopeExceedsCeilingError } from '../auth/ceiling.js';

export interface SafeValidationIssue {
  path: string;
  code: string;
  message?: string;
}

export class RequestValidationError extends AgentScopeError {
  constructor(
    public readonly issues: SafeValidationIssue[],
    public readonly httpStatus = 400,
  ) {
    super('VALIDATION_FAILED', 'Request validation failed.', { issues });
    this.name = 'RequestValidationError';
  }
}

export class RateLimitExceededError extends AgentScopeError {
  constructor(
    public readonly operation: string,
    public readonly limit: number,
    public readonly windowMs: number,
    public readonly retryAfterSeconds: number,
  ) {
    super(
      'RATE_LIMITED',
      `${operationLabel(operation)} rate limit exceeded (${limit}/${windowLabel(windowMs)}). Retry after ${retryAfterSeconds}s.`,
      { operation, limit, windowMs, retryAfterSeconds },
    );
    this.name = 'RateLimitExceededError';
  }
}

export interface NormalizedDomainError {
  code: string;
  message: string;
  httpStatus: number;
  details?: Record<string, unknown>;
  retryAfterSeconds?: number;
}

const STATUS_BY_CODE: Record<string, number> = {
  VALIDATION_FAILED: 400,
  QUERY_REJECTED: 400,
  CREDENTIAL_MALFORMED: 400,
  CREDENTIAL_INVALID: 401,
  UNKNOWN_ISSUER: 401,
  DID_RESOLUTION_FAILED: 401,
  AUTH_UNAVAILABLE: 503,
  DB_CONNECTION_FAILED: 503,
  AUDIT_WRITE_FAILED: 503,
  CREDENTIAL_EXPIRED: 403,
  CREDENTIAL_REVOKED: 403,
  CREDENTIAL_REPLAYED: 403,
  SCOPE_VIOLATION: 403,
  SCOPE_EXCEEDS_CEILING: 403,
  POLICY_VIOLATION: 403,
  FORBIDDEN_CREDENTIAL: 403,
  CAPABILITY_REQUIRES_PAID_TIER: 402,
  RATE_LIMITED: 429,
};

const SAFE_PUBLIC_MESSAGE_CODES = new Set([
  'QUERY_REJECTED',
  'CREDENTIAL_MALFORMED',
  'CREDENTIAL_INVALID',
  'CREDENTIAL_EXPIRED',
  'CREDENTIAL_REVOKED',
  'CREDENTIAL_REPLAYED',
  'UNKNOWN_ISSUER',
  'SCOPE_EXCEEDS_CEILING',
  'POLICY_VIOLATION',
  'FORBIDDEN_CREDENTIAL',
  'CAPABILITY_REQUIRES_PAID_TIER',
]);

const SAFE_MESSAGE_BY_CODE: Record<string, string> = {
  DID_RESOLUTION_FAILED: 'Identifier resolution failed.',
  AUTH_UNAVAILABLE: 'Authentication provider unavailable.',
  DB_CONNECTION_FAILED: 'Database dependency unavailable.',
  AUDIT_WRITE_FAILED: 'Audit write failed.',
};

export function normalizeDomainError(err: unknown): NormalizedDomainError {
  if (err instanceof RequestValidationError) {
    return {
      code: err.code,
      message: err.message,
      httpStatus: err.httpStatus,
      details: { issues: err.issues },
    };
  }

  if (err instanceof RateLimitExceededError) {
    return {
      code: err.code,
      message: err.message,
      httpStatus: STATUS_BY_CODE[err.code],
      retryAfterSeconds: err.retryAfterSeconds,
    };
  }

  if (err instanceof ScopeViolationError) {
    const safe = err.toSafeResponse();
    return {
      code: safe.code,
      message: safe.message,
      httpStatus: STATUS_BY_CODE[safe.code],
    };
  }

  if (err instanceof ScopeExceedsCeilingError) {
    return {
      code: err.code,
      message: err.message,
      httpStatus: STATUS_BY_CODE[err.code],
      details: {
        ceiling: {
          columns: err.ceiling.columns,
          actions: err.ceiling.actions,
          source: err.ceiling.source,
          resolvedFrom: err.ceiling.resolvedFrom,
        },
        excess: err.excess,
      },
    };
  }

  if (err instanceof AgentScopeError) {
    const status = STATUS_BY_CODE[err.code] ?? 400;
    return {
      code: err.code,
      message: safeMessageForCode(err.code, err),
      httpStatus: status,
    };
  }

  if (hasStringCode(err)) {
    return {
      code: err.code,
      message: safeMessageForCode(err.code, err instanceof Error ? err : undefined),
      httpStatus: STATUS_BY_CODE[err.code] ?? 400,
    };
  }

  return {
    code: 'INTERNAL_ERROR',
    message: 'An internal error occurred.',
    httpStatus: 500,
  };
}

export function toHttpErrorBody(error: NormalizedDomainError): Record<string, unknown> {
  return compactObject({
    error: error.code,
    code: error.code,
    message: error.message,
    details: error.details,
    retryAfterSeconds: error.retryAfterSeconds,
  });
}

export function toMcpErrorBody(error: NormalizedDomainError): Record<string, unknown> {
  return compactObject({
    error: error.code,
    message: error.message,
    details: error.details,
    retryAfterSeconds: error.retryAfterSeconds,
  });
}

function safeMessageForCode(code: string, err?: Error): string {
  if (SAFE_PUBLIC_MESSAGE_CODES.has(code) && err?.message) return err.message;
  return SAFE_MESSAGE_BY_CODE[code] ?? 'Request failed.';
}

function hasStringCode(value: unknown): value is { code: string } {
  return (
    !!value &&
    typeof value === 'object' &&
    'code' in value &&
    typeof (value as { code?: unknown }).code === 'string'
  );
}

function compactObject<T extends Record<string, unknown>>(value: T): T {
  for (const key of Object.keys(value)) {
    if (value[key] === undefined) delete value[key];
  }
  return value;
}

function operationLabel(operation: string): string {
  if (!operation) return 'Operation';
  return `${operation.charAt(0).toUpperCase()}${operation.slice(1)}`;
}

function windowLabel(windowMs: number): string {
  if (windowMs === 60_000) return 'min';
  return `${Math.ceil(windowMs / 1000)}s`;
}
