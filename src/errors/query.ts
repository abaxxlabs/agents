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
 * SQL parse failure, mutation detected, or non-SELECT statement.
 * Distinct from CredentialInvalidError -- the credential may be perfectly valid,
 * but the query itself is rejected.
 */
export class QueryRejectedError extends AgentScopeError {
  constructor(agentDid: string, reason: string) {
    super('QUERY_REJECTED', `Query rejected for agent ${agentDid} — ${reason}`, { agentDid });
    this.name = 'QueryRejectedError';
  }
}

/**
 * Query references columns outside the credential's authorized scope.
 * HTTP responses must NOT include column names (schema-oracle prevention).
 * Internal audit records DO include the full detail.
 */
export class ScopeViolationError extends AgentScopeError {
  constructor(
    agentDid: string,
    /** Columns requested that are out of scope -- included in audit, stripped from HTTP responses */
    public readonly requestedColumns: string[],
    /** Columns the credential authorizes */
    public readonly authorizedColumns: string[],
  ) {
    super('SCOPE_VIOLATION', `Agent ${agentDid} queried columns outside credential scope`, {
      agentDid,
    });
    this.name = 'ScopeViolationError';
  }

  /** Coarsened JSON for HTTP responses -- omits column names to prevent schema enumeration attacks. */
  toSafeResponse(): { code: string; message: string } {
    return {
      code: this.code,
      message:
        'Query references columns outside the authorized scope. Request a credential with broader scope.',
    };
  }
}
