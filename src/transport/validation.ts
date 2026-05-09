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
 * Shared request schemas for REST bodies/query strings and MCP tool inputs.
 * Defined once; REST uses strict objects, MCP uses the same shapes directly.
 * Validation errors expose only issue paths and codes, never submitted values.
 */

import { z, type ZodIssue } from 'zod';
import { RequestValidationError, type SafeValidationIssue } from './errors.js';
import { expiresInToMs, parseDuration } from '../config.js';

export type RequestSchema<T> = z.ZodType<T>;

export const SIGN_PAYLOAD_MAX_BYTES = 64 * 1024;
export const SQL_MAX_CHARS = 64 * 1024;
export const JWT_MAX_CHARS = 100 * 1024;

const principalString = z.string().min(1).max(2048);
const shortString = z.string().min(1).max(512);
const agentName = z.string().min(1).max(128);
const actionString = z.literal('read');
const columnString = z.string().min(1).max(256);
const jwtString = z.string().min(1).max(JWT_MAX_CHARS);
const sqlString = z.string().min(1).max(SQL_MAX_CHARS);

const expiresInDurationString = z
  .string()
  .min(1)
  .max(32)
  .superRefine((val, ctx) => {
    try {
      const ms = parseDuration(val);
      if (ms <= 0) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'Duration must be positive' });
      }
    } catch {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'Invalid duration format. Expected: "4h", "1d", "30m", etc.',
      });
    }
  });

const expiresInField = z.union([
  expiresInDurationString,
  z.number().int().positive().max(31_536_000),
]);

const tableName = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[a-zA-Z_][a-zA-Z0-9_]*(\.[a-zA-Z_][a-zA-Z0-9_]*)?$/);

const optionalIsoDateString = z
  .string()
  .min(1)
  .max(64)
  .refine((value) => !Number.isNaN(new Date(value).getTime()), {
    message: 'Invalid date-time',
  })
  .optional();

const queryLimit = (defaultValue: number, max: number) =>
  z
    .preprocess((value) => {
      if (value === undefined) return undefined;
      if (typeof value === 'string' && value.trim() !== '') return Number(value);
      return value;
    }, z.number().int().min(1).max(max).optional())
    .transform((value) => value ?? defaultValue);

const optionalBodyLimit = (defaultValue: number, max: number) =>
  z
    .preprocess((value) => {
      if (value === undefined) return undefined;
      return value;
    }, z.number().int().min(1).max(max).optional())
    .transform((value) => value ?? defaultValue);

const strictObject = <Shape extends z.ZodRawShape>(shape: Shape) => z.object(shape).strict();

export const authSessionBodySchema = strictObject({
  mockHumanDid: shortString.optional(),
});

export const createAgentBodyShape = {
  name: agentName,
};
export const createAgentBodySchema = strictObject(createAgentBodyShape);

export const listAgentsQuerySchema = strictObject({
  owner: principalString.optional(),
  limit: queryLimit(100, 100),
});

export const issueCredentialBodyShape = {
  agent: principalString,
  columns: z.array(columnString).min(1).max(100),
  actions: z.array(actionString).min(1).max(16),
  expiresIn: expiresInField,
};
export const issueCredentialBodySchema = strictObject(issueCredentialBodyShape);

export const delegateCredentialBodyShape = {
  sourceCredential: jwtString,
  targetAgent: principalString,
  columns: z.array(columnString).min(1).max(100),
  actions: z.array(actionString).min(1).max(16),
  expiresIn: expiresInField,
};
export const delegateCredentialBodySchema = strictObject(delegateCredentialBodyShape);

export const listCredentialsQuerySchema = strictObject({
  agentDid: principalString.optional(),
  issuedAfter: optionalIsoDateString,
  limit: queryLimit(100, 500),
});

export const queryBodyShape = {
  agent: principalString,
  credential: jwtString,
  table: tableName,
  sql: sqlString,
  params: z.array(z.unknown()).max(100).optional(),
};
export const queryBodySchema = strictObject(queryBodyShape);

export const auditQuerySchema = strictObject({
  agent: principalString.optional(),
  since: optionalIsoDateString,
  orgId: principalString.optional(),
  limit: queryLimit(50, 500),
});

export const verifyAuditBodyShape = {
  auditId: shortString,
};
export const verifyAuditBodySchema = strictObject(verifyAuditBodyShape);

export const verifyChainBodyShape = {
  limit: optionalBodyLimit(1000, 1000),
};
export const verifyChainBodySchema = strictObject(verifyChainBodyShape);

export const signBodyShape = {
  payload: z.string().max(SIGN_PAYLOAD_MAX_BYTES),
};
export const signBodySchema = strictObject(signBodyShape);

export const challengeBodyShape = {
  requestorDid: principalString.optional(),
  ttlSeconds: z.number().int().min(1).max(300).optional(),
};
export const challengeBodySchema = strictObject(challengeBodyShape);

export const mcpSseQuerySchema = strictObject({
  'x-session': principalString,
});

export const mcpMessagesQuerySchema = strictObject({
  sessionId: shortString,
});

export const emptyBodySchema = strictObject({});
export const emptyQuerySchema = strictObject({});

export const restValidationSchemas = {
  authSessionBody: authSessionBodySchema,
  createAgentBody: createAgentBodySchema,
  listAgentsQuery: listAgentsQuerySchema,
  issueCredentialBody: issueCredentialBodySchema,
  delegateCredentialBody: delegateCredentialBodySchema,
  listCredentialsQuery: listCredentialsQuerySchema,
  queryBody: queryBodySchema,
  auditQuery: auditQuerySchema,
  verifyAuditBody: verifyAuditBodySchema,
  verifyChainBody: verifyChainBodySchema,
  signBody: signBodySchema,
  challengeBody: challengeBodySchema,
  mcpSseQuery: mcpSseQuerySchema,
  mcpMessagesQuery: mcpMessagesQuerySchema,
  emptyBody: emptyBodySchema,
  emptyQuery: emptyQuerySchema,
};

export const mcpToolInputShapes = {
  query: queryBodyShape,
  sign: signBodyShape,
  challenge: challengeBodyShape,
};

export function validateRequest<T>(schema: RequestSchema<T>, input: unknown): T {
  const result = schema.safeParse(input);
  if (!result.success) {
    throw new RequestValidationError(result.error.issues.map(toSafeValidationIssue));
  }
  return result.data;
}

export function assertUtf8MaxBytes(path: string, value: string, maxBytes: number): void {
  if (Buffer.from(value, 'utf-8').length > maxBytes) {
    throw new RequestValidationError([{ path, code: 'too_big' }], 413);
  }
}

/**
 * Reject expiresIn values that exceed the configured credential maxTtl.
 * Call after Zod schema validation in route/tool handlers where config is available.
 *
 * @throws RequestValidationError with a 400 status naming the violated bound
 */
export function assertExpiresInBound(
  expiresIn: string | number,
  maxTtlMs: number,
): void {
  if (expiresInToMs(expiresIn) > maxTtlMs) {
    const maxSeconds = Math.floor(maxTtlMs / 1_000);
    throw new RequestValidationError([
      {
        path: 'expiresIn',
        code: 'too_big',
        message: `expiresIn exceeds maximum credential TTL of ${maxSeconds}s`,
      },
    ]);
  }
}

function toSafeValidationIssue(issue: ZodIssue): SafeValidationIssue {
  return {
    path: issue.path.length > 0 ? issue.path.map(String).join('.') : '<root>',
    code: issue.code,
  };
}
