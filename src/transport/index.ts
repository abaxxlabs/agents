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

export {
  RequestValidationError,
  RateLimitExceededError,
  normalizeDomainError,
  toHttpErrorBody,
  toMcpErrorBody,
  type NormalizedDomainError,
  type SafeValidationIssue,
} from './errors.js';

export {
  FixedWindowRateLimiter,
  defaultIdentityRateLimiter,
  assertWithinRateLimit,
  rateLimitBucketKey,
  SIGN_RATE_LIMIT,
  SIGN_RATE_WINDOW_MS,
  CHALLENGE_RATE_LIMIT,
  CHALLENGE_RATE_WINDOW_MS,
  type RateLimiter,
  type RateLimitCheck,
  type RateLimitDecision,
} from './rate-limit.js';

export {
  SIGN_PAYLOAD_MAX_BYTES,
  SQL_MAX_CHARS,
  JWT_MAX_CHARS,
  assertExpiresInBound,
  assertUtf8MaxBytes,
  challengeBodySchema,
  createAgentBodySchema,
  delegateCredentialBodySchema,
  issueCredentialBodySchema,
  listAgentsQuerySchema,
  listCredentialsQuerySchema,
  mcpMessagesQuerySchema,
  mcpSseQuerySchema,
  mcpToolInputShapes,
  queryBodySchema,
  restValidationSchemas,
  signBodySchema,
  validateRequest,
  verifyAuditBodySchema,
  verifyChainBodySchema,
  type RequestSchema,
} from './validation.js';
