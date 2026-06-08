import { AgentScopeError } from './base.js';

export class CredentialInvalidError extends AgentScopeError {
  constructor(agentDid: string, reason?: string) {
    super(
      'CREDENTIAL_INVALID',
      `Signature verification failed for agent ${agentDid}${reason ? ` — ${reason}` : ''}`,
      { agentDid },
    );
    this.name = 'CredentialInvalidError';
  }
}

export class CredentialExpiredError extends AgentScopeError {
  constructor(agentDid: string, expiredAt: Date) {
    super(
      'CREDENTIAL_EXPIRED',
      `Credential for agent ${agentDid} expired at ${expiredAt.toISOString()} (current: ${new Date().toISOString()})`,
      { agentDid, expiredAt: expiredAt.toISOString() },
    );
    this.name = 'CredentialExpiredError';
  }
}

export class CredentialRevokedError extends AgentScopeError {
  constructor(credentialId: string, issuerDid: string, suspended = false) {
    super(
      'CREDENTIAL_REVOKED',
      `Credential ${credentialId} has been ${suspended ? 'suspended' : 'revoked'} by issuer ${issuerDid}`,
      { credentialId, issuerDid, suspended },
    );
    this.name = 'CredentialRevokedError';
  }
}

export class CredentialMalformedError extends AgentScopeError {
  constructor(reason: string) {
    super(
      'CREDENTIAL_MALFORMED',
      `Credential JWT missing required claim — ${reason}. Expected schema: https://abaxx.tech/schemas/agents-v1`,
      {},
    );
    this.name = 'CredentialMalformedError';
  }
}

export class UnknownIssuerError extends AgentScopeError {
  constructor(issuerDid: string, reason?: string) {
    super(
      'UNKNOWN_ISSUER',
      `Could not resolve issuer ${issuerDid}${reason ? ` — ${reason}` : ''}`,
      { issuerDid },
    );
    this.name = 'UnknownIssuerError';
  }
}

/**
 * Credential JTI has already been consumed (replay protection).
 * Distinct from CredentialInvalidError -- the credential was valid when first
 * presented but cannot be reused. Includes JTI and recovery instruction so the
 * caller knows exactly what happened and how to fix it.
 */
export class CredentialReplayedError extends AgentScopeError {
  constructor(
    agentDid: string,
    public readonly jti: string,
  ) {
    super(
      'CREDENTIAL_REPLAYED',
      `Credential ${jti} for agent ${agentDid} has already been used. Issue a new credential with issueCredential().`,
      { agentDid, jti },
    );
    this.name = 'CredentialReplayedError';
  }
}
