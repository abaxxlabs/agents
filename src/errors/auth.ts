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
