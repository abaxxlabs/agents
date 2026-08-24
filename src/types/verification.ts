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
    | 'POLICY_VIOLATION'
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
