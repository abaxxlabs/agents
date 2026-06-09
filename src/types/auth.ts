import type { ScopeCeiling } from '#auth/ceiling.js';
import type { IssueCredentialOptions } from './credential.js';

export interface AuthOptions {
  redirectUri?: string;
  mockHumanDid?: string;
  oidcIdentity?: {
    humanDid: string;
    issuer: string;
    sub: string;
    email?: string;
    name?: string;
    org?: string;
  };
  scopeCeiling?: ScopeCeiling;
}

export interface AuthenticatedSession {
  humanDid: string;
  email?: string;
  scopeCeiling: ScopeCeiling;
  parentIssuerDid?: string;
  parentCredentialExp?: number;
  issueCredential(options: IssueCredentialOptions): Promise<string>;
  revokeCredential(credentialId: string): Promise<{ sdkNotificationFailed?: Error }>;
}

export interface CreateAgentOptions {
  name: string;
  ownerDid?: string;
}

/** Opaque signing handle -- wraps a private key without exposing it. */
export interface AgentSigner {
  /** Sign a JWT payload, returning a compact JWS string (EdDSA / Ed25519). */
  signJwt(payload: Record<string, unknown>): Promise<string>;
}

export interface RegisteredAgent {
  did: string;
  name: string;
  ownerDid: string;
  signer: AgentSigner;
  publicKey: Uint8Array;
}
