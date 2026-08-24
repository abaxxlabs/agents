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

import { AgentScopeError } from './base.js';

/**
 * Thrown when requesting a parent-issued agent credential from AbaxxOne fails.
 * Includes tenant URL, HTTP status, and a recovery hint so the error is actionable.
 */
export class ParentCredentialRequestFailedError extends AgentScopeError {
  constructor(
    public readonly tenantUrl: string,
    public readonly httpStatus: number | undefined,
    recoveryHint?: string,
  ) {
    super(
      'PARENT_CREDENTIAL_REQUEST_FAILED',
      `Failed to obtain agent credential from parent instance at ${tenantUrl}` +
        (httpStatus ? ` (HTTP ${httpStatus})` : '') +
        `. ${recoveryHint ?? 'Check that the tenant URL is correct and the access token is valid.'}`,
      { tenantUrl, httpStatus },
    );
    this.name = 'ParentCredentialRequestFailedError';
  }
}

export class TtlExceededError extends AgentScopeError {
  constructor(maxTtlMs: number) {
    const maxSeconds = Math.floor(maxTtlMs / 1_000);
    super('TTL_EXCEEDED', `expiresIn exceeds maximum credential TTL of ${maxSeconds}s`, {
      maxTtlMs,
      maxSeconds,
    });
    this.name = 'TtlExceededError';
  }
}

export class PrecisionLossError extends AgentScopeError {
  constructor(rawValue: string) {
    super(
      'PRECISION_LOSS',
      `PostgreSQL bigint value '${rawValue}' exceeds Number.MAX_SAFE_INTEGER and cannot be safely represented as a JavaScript number`,
      { rawValue },
    );
    this.name = 'PrecisionLossError';
  }
}

export class CapabilityRequiresPaidTierError extends AgentScopeError {
  constructor(
    public readonly capability: string,
    public readonly namespace: string,
  ) {
    super(
      'CAPABILITY_REQUIRES_PAID_TIER',
      `Capability "${capability}" in namespace "${namespace}" requires AbaxxOne. Sign up at https://abaxx.tech/one`,
      { capability, namespace, signupUrl: 'https://abaxx.tech/one' },
    );
    this.name = 'CapabilityRequiresPaidTierError';
  }
}
