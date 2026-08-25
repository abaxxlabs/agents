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

export class AuthUnavailableError extends AgentScopeError {
  constructor(tenantUrl: string) {
    super(
      'AUTH_UNAVAILABLE',
      `Cannot reach Abaxx One at ${tenantUrl} — human authentication unavailable. Existing credentials remain valid until expiry.`,
      { tenantUrl },
    );
    this.name = 'AuthUnavailableError';
  }
}

export class DiscoveryEndpointBlockedError extends AgentScopeError {
  constructor(
    field: string,
    endpointHost: string,
    issuerOrigin: string,
    public readonly configMissing: boolean,
    providerLabel?: string,
  ) {
    const reason = configMissing
      ? 'no allowedCrossOriginHosts configured for this issuer'
      : `host is not in the issuer's allowedCrossOriginHosts`;
    const prefix = providerLabel ? `${providerLabel} discovery` : 'OIDC discovery';
    super(
      'DISCOVERY_ENDPOINT_BLOCKED',
      `${prefix} ${field} blocked: endpoint host "${endpointHost}" differs from issuer origin ${issuerOrigin} — ${reason}`,
      { field, endpointHost, issuerOrigin, configMissing },
    );
    this.name = 'DiscoveryEndpointBlockedError';
  }
}
