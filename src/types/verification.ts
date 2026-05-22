import type { CredentialScope } from './credential.js';
import type { MigrationCredentialClaims } from './migration.js';

export interface VerifyOptions {
  skipScopeCheck?: boolean;
  expectedSubject?: string;
  expectedAudience?: string;
}

export interface VerificationResult {
  valid: boolean;
  status:
    | 'VALID'
    | 'INVALID_SIGNATURE'
    | 'EXPIRED'
    | 'REVOKED'
    | 'SUSPENDED'
    | 'UNKNOWN_ISSUER'
    | 'MALFORMED'
    | 'REPLAYED'
    | 'WRONG_SUBJECT'
    | 'WRONG_AUDIENCE'
    | 'MIGRATION_DETECTED';
  credential?: DecodedCredential;
  error?: string;
}

export interface DecodedCredential {
  issuer: string;
  subject: string;
  issuedAt: Date;
  expiresAt: Date;
  scope?: CredentialScope;
  credentialStatus?: {
    id: string;
    type: string;
    statusPurpose: string;
    statusListIndex: string;
    statusListCredential: string;
  };
  vcTypes?: string[];
  delegationChain?: string[];
  migrationClaims?: MigrationCredentialClaims;
}
