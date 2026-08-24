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

import { parseDuration } from '#config.js';
import { base58Decode } from '#crypto/base58.js';
import type { RevocationStore } from '#storage/types.js';
import type {
  CredentialScope,
  Did,
  IdSdkInstance,
  VerifyOptions,
  VerificationResult,
  DecodedCredential,
  MigrationCredentialClaims,
} from '#types/index.js';
import { IDENTITY_MIGRATION_CREDENTIAL } from '#types/index.js';
import { CredentialMalformedError, DidResolutionFailedError } from '#errors/index.js';

import { decodeJwt, verifyJwtSignature } from '#crypto/jwt.js';
import { isDelegatedScopeCredentialType } from '#auth/credential-issuance.js';
import { DidCache } from '#did/cache.js';
import { resolveDidKeyFallback } from '#did/resolve.js';
import { numericDateToMs } from './numeric-date.js';
import { ReplayGuard, verifyPresentation } from './vp-verification.js';
import { checkDelegationChainRevocation, checkDelegationDepthCeiling } from './delegation-chain.js';

export interface RevocationTelemetryEvent {
  source: 'local_store' | 'credential_status';
  credentialId?: string;
  outcome: 'not_revoked' | 'revoked' | 'suspended' | 'failed';
  error?: unknown;
}

export interface VcVerifierOptions {
  /**
   * Symmetric tolerance applied to VP timestamp checks only. Default: `'5s'`.
   *
   * Maximum: 30 seconds.
   */
  clockSkew?: string;
  resolverCacheTtl?: string;
  /** Enable JTI-based VP replay protection. VCs remain reusable. Default: true. */
  replayProtection?: boolean;
  /** Max JTI cache entries before forced eviction. Default: 100_000 */
  maxReplayCacheSize?: number;
  /** Platform identity handle. */
  sdk?: IdSdkInstance;
  /** Pre-registered DID -> publicKey map. */
  knownKeys?: Map<string, Uint8Array>;
  /**
   * Pluggable revocation store. REQUIRED.
   *
   * Consumers must declare their revocation posture explicitly. There is no
   * default in-memory fallback: a missing store is a deployment-time error,
   * not a silent regression.
   */
  revocationStore: RevocationStore;
}

export interface VcVerifierTelemetrySink {
  revocationCheck(event: RevocationTelemetryEvent): void;
}

export class VcVerifier {
  private cache: DidCache;
  private clockSkewMs: number;
  private knownKeys: Map<string, Uint8Array>;
  private sdk: IdSdkInstance | undefined;
  private readonly revocationStore: RevocationStore;
  private telemetry?: VcVerifierTelemetrySink;
  private readonly replayGuard: ReplayGuard;

  constructor(options: VcVerifierOptions) {
    this.cache = new DidCache(options.resolverCacheTtl ?? '5m');
    const MAX_CLOCK_SKEW_MS = 30 * 1_000;
    this.clockSkewMs = parseDuration(options.clockSkew ?? '5s');
    if (this.clockSkewMs <= 0) {
      throw new Error(
        'clockSkew must be greater than zero. Zero tolerance causes false rejections under any clock drift',
      );
    }
    if (this.clockSkewMs > MAX_CLOCK_SKEW_MS) {
      throw new Error(
        'clockSkew exceeds maximum of 30 seconds. ' +
          'this is machine-to-machine auth; values beyond NTP-realistic drift extend VP lifetime, not clock tolerance',
      );
    }
    this.knownKeys = options.knownKeys ?? new Map();
    this.sdk = options.sdk;
    this.revocationStore = options.revocationStore;
    this.replayGuard = new ReplayGuard(
      options.maxReplayCacheSize ?? 100_000,
      options.replayProtection ?? true,
    );
  }

  /**
   * Attach a best-effort operational telemetry sink.
   */
  setTelemetrySink(sink: VcVerifierTelemetrySink | undefined): void {
    this.telemetry = sink;
  }

  private emitRevocationTelemetry(event: RevocationTelemetryEvent): void {
    try {
      this.telemetry?.revocationCheck(event);
    } catch {
      // Operational telemetry is best-effort and must not alter verification.
    }
  }

  /** Set the platform identity handle (can be set after construction). */
  setSdk(sdk: IdSdkInstance): void {
    this.sdk = sdk;
  }

  /**
   * Revoke a credential by its JTI.
   *
   * @param credentialId - JTI of the credential to revoke.
   * @param opts.reason - Optional human-readable reason.
   * @param opts.credentialExp - Credential's original exp claim (for pruning).
   * @throws if the revocation store fails to persist the revocation.
   */
  async revokeAsync(
    credentialId: string,
    opts: { reason?: string; credentialExp?: Date } = {},
  ): Promise<void> {
    await this.revocationStore.revoke(credentialId, opts);
  }

  /** Check whether a credential JTI has been revoked. */
  async isRevoked(credentialId: string): Promise<boolean> {
    return this.revocationStore.isRevoked(credentialId);
  }

  /** Register a DID's public key (used at agent creation time). */
  registerKey(did: string, publicKey: Uint8Array): void {
    const brandedDid = did as Did;
    this.knownKeys.set(did, publicKey);
    this.cache.set(brandedDid, publicKey);
  }

  /**
   * Resolve a DID to its public key.
   * Uses the injected platform DID resolver when available, falls back to known
   * keys and did:key parsing.
   */
  async resolvePublicKey(did: string): Promise<Uint8Array> {
    const brandedDid = did as Did;
    const cached = this.cache.get(brandedDid);
    if (cached) return cached;

    const known = this.knownKeys.get(did);
    if (known) {
      this.cache.set(brandedDid, known);
      return known;
    }

    if (this.sdk) {
      try {
        const result = await this.sdk.did.resolve(did);
        const doc = result.didDocument as
          | {
              verificationMethod?: Array<{
                publicKeyJwk?: { x: string };
                publicKeyMultibase?: string;
              }>;
            }
          | undefined;
        if (!doc || !doc.verificationMethod || doc.verificationMethod.length === 0) {
          throw new DidResolutionFailedError(did, 'No verification methods in DID document');
        }

        const vm = doc.verificationMethod[0];
        let publicKey: Uint8Array;

        if (vm.publicKeyJwk) {
          const xBytes = Buffer.from(vm.publicKeyJwk.x, 'base64url');
          publicKey = new Uint8Array(xBytes);
        } else if (vm.publicKeyMultibase) {
          const encoded = vm.publicKeyMultibase.slice(1);
          publicKey = base58Decode(encoded);
          if (publicKey[0] === 0xed && publicKey[1] === 0x01) {
            publicKey = publicKey.slice(2);
          }
        } else {
          throw new DidResolutionFailedError(did, 'No supported key format in DID document');
        }

        this.cache.set(brandedDid, publicKey);
        return publicKey;
      } catch (err) {
        if (err instanceof DidResolutionFailedError) throw err;
        throw new DidResolutionFailedError(
          did,
          err instanceof Error ? err.message : 'Unknown resolution error',
        );
      }
    }

    if (did.startsWith('did:key:z')) {
      const pk = resolveDidKeyFallback(brandedDid);
      this.cache.set(brandedDid, pk);
      return pk;
    }

    throw new DidResolutionFailedError(
      did,
      `Cannot resolve ${did}. No platform DID resolver available and not a did:key`,
    );
  }

  /**
   * Verify a VC or VP JWT. VP timestamps use configured clock skew; VC timestamps are strict.
   * Replay protection applies only to VPs that contain a JTI.
   *
   * @param jwt    The credential JWT to verify.
   * @param options  Optional verification controls.
   */
  async verify(jwt: string, options: VerifyOptions = {}): Promise<VerificationResult> {
    let decoded: ReturnType<typeof decodeJwt>;
    try {
      decoded = decodeJwt(jwt);
    } catch {
      return { valid: false, status: 'MALFORMED', error: 'Failed to decode JWT' };
    }

    const { payload } = decoded;

    // VP detection
    const vpClaim = payload.vp as { type?: string[]; verifiableCredential?: string[] } | undefined;
    if (vpClaim?.type?.includes?.('VerifiablePresentation')) {
      return verifyPresentation(jwt, payload, vpClaim, options, {
        clockSkewMs: this.clockSkewMs,
        replayGuard: this.replayGuard,
        resolvePublicKey: (d) => this.resolvePublicKey(d),
        verifyInnerCredential: (j, o) => this.verify(j, o),
      });
    }

    if (!payload.iss) {
      return { valid: false, status: 'MALFORMED', error: 'Missing issuer (iss) claim' };
    }
    if (!payload.sub) {
      return { valid: false, status: 'MALFORMED', error: 'Missing subject (sub) claim' };
    }

    const scope = payload.vc?.credentialSubject?.scope;
    if (!options.skipScopeCheck) {
      if (!scope || !scope.columns || !Array.isArray(scope.columns)) {
        return {
          valid: false,
          status: 'MALFORMED',
          error: "Missing or invalid 'scope' in credentialSubject",
        };
      }
    }

    const now = Date.now();
    const iatMs = payload.iat !== undefined ? numericDateToMs(payload.iat) : null;
    if (payload.iat !== undefined && iatMs === null) {
      return {
        valid: false,
        status: 'MALFORMED',
        error: 'Credential iat is not a valid NumericDate',
      };
    }

    const nbfMs = payload.nbf !== undefined ? numericDateToMs(payload.nbf) : iatMs;
    if (payload.nbf !== undefined && nbfMs === null) {
      return {
        valid: false,
        status: 'MALFORMED',
        error: 'Credential nbf is not a valid NumericDate',
      };
    }

    if (nbfMs !== null) {
      if (now < nbfMs) {
        return {
          valid: false,
          status: 'MALFORMED',
          error: `Credential not valid until ${new Date(nbfMs).toISOString()}`,
        };
      }
    }

    const expMs = payload.exp !== undefined ? numericDateToMs(payload.exp) : null;
    if (payload.exp !== undefined && expMs === null) {
      return {
        valid: false,
        status: 'MALFORMED',
        error: 'Credential exp is not a valid NumericDate',
      };
    }
    if (expMs !== null) {
      if (now >= expMs) {
        return {
          valid: false,
          status: 'EXPIRED',
          error: `Credential expired at ${new Date(expMs).toISOString()}`,
        };
      }
    }

    // Signature verification
    let sigValid: boolean;
    if (this.sdk) {
      try {
        sigValid = await this.sdk.vc.verifyJWT(jwt);
      } catch {
        sigValid = false;
      }
    } else {
      let publicKey: Uint8Array;
      try {
        publicKey = await this.resolvePublicKey(payload.iss);
      } catch (err) {
        if (err instanceof DidResolutionFailedError) {
          return { valid: false, status: 'UNKNOWN_ISSUER', error: err.message };
        }
        throw err;
      }
      sigValid = await verifyJwtSignature(jwt, publicKey);
    }

    if (!sigValid) {
      return {
        valid: false,
        status: 'INVALID_SIGNATURE',
        error: 'JWT signature verification failed',
      };
    }

    // Subject binding (prevents confused-deputy attacks)
    if (options.expectedSubject && payload.sub !== options.expectedSubject) {
      return {
        valid: false,
        status: 'WRONG_SUBJECT',
        error: `Credential subject mismatch: expected ${options.expectedSubject}, got ${payload.sub}`,
      };
    }

    // Audience binding (prevents VP replay across servers)
    if (options.expectedAudience && payload.aud) {
      const audClaim = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
      if (!audClaim.includes(options.expectedAudience)) {
        return {
          valid: false,
          status: 'WRONG_AUDIENCE',
          error: `Credential audience mismatch: expected ${options.expectedAudience}, got ${audClaim.join(', ')}`,
        };
      }
    }

    // Revocation check
    if (payload.jti) {
      let revoked: boolean;
      try {
        revoked = await this.revocationStore.isRevoked(payload.jti);
      } catch (err) {
        this.emitRevocationTelemetry({
          source: 'local_store',
          credentialId: payload.jti,
          outcome: 'failed',
          error: err,
        });
        throw err;
      }
      this.emitRevocationTelemetry({
        source: 'local_store',
        credentialId: payload.jti,
        outcome: revoked ? 'revoked' : 'not_revoked',
      });
      if (revoked) {
        return { valid: false, status: 'REVOKED', error: 'Credential has been revoked' };
      }
    }

    // Delegation chain structural checks
    const rawVcType = payload.vc?.type;
    const vcTypes: string[] | undefined = Array.isArray(rawVcType)
      ? rawVcType
      : typeof rawVcType === 'string'
        ? [rawVcType]
        : undefined;
    const delegationChain: string[] | undefined = Array.isArray(payload.delegationChain)
      ? payload.delegationChain
      : undefined;
    if (delegationChain !== undefined && delegationChain.length === 0) {
      return {
        valid: false,
        status: 'MALFORMED',
        error:
          'Credential has empty delegationChain -- a delegated credential must have at least one ancestor.',
      };
    }
    const isDelegatedType = vcTypes !== undefined && isDelegatedScopeCredentialType(vcTypes);
    const hasChain =
      delegationChain !== undefined &&
      delegationChain.some((e): e is string => typeof e === 'string');
    if (isDelegatedType && !hasChain) {
      return {
        valid: false,
        status: 'MALFORMED',
        error: 'DelegatedAgentScopeCredential must include a non-empty delegationChain.',
      };
    }
    if (hasChain && !isDelegatedType) {
      return {
        valid: false,
        status: 'MALFORMED',
        error: 'Credential with delegationChain must declare type DelegatedAgentScopeCredential.',
      };
    }

    const chainResult = await checkDelegationChainRevocation(payload.delegationChain, {
      revocationStore: this.revocationStore,
      knownKeys: this.knownKeys,
      sdk: this.sdk,
      emitRevocationTelemetry: (e) => this.emitRevocationTelemetry(e),
    });
    if (chainResult) return chainResult;

    const depthResult = checkDelegationDepthCeiling(payload);
    if (depthResult) return depthResult;

    // SDK credential status (StatusList 2021)
    if (this.sdk && payload.vc?.credentialStatus) {
      try {
        const status = await this.sdk.vc.checkCredentialStatus({
          credentialId: payload.vc.credentialStatus.id,
          statusListCredentialId: payload.vc.credentialStatus.statusListCredential,
          statusListIndex: payload.vc.credentialStatus.statusListIndex
            ? parseInt(payload.vc.credentialStatus.statusListIndex, 10)
            : undefined,
        });
        if (status.revoked) {
          this.emitRevocationTelemetry({
            source: 'credential_status',
            credentialId: payload.vc.credentialStatus.id,
            outcome: 'revoked',
          });
          return { valid: false, status: 'REVOKED', error: 'Credential has been revoked' };
        }
        if (status.suspended) {
          this.emitRevocationTelemetry({
            source: 'credential_status',
            credentialId: payload.vc.credentialStatus.id,
            outcome: 'suspended',
          });
          return { valid: false, status: 'SUSPENDED', error: 'Credential has been suspended' };
        }
        this.emitRevocationTelemetry({
          source: 'credential_status',
          credentialId: payload.vc.credentialStatus.id,
          outcome: 'not_revoked',
        });
      } catch {
        this.emitRevocationTelemetry({
          source: 'credential_status',
          credentialId: payload.vc.credentialStatus.id,
          outcome: 'failed',
        });
        return {
          valid: false,
          status: 'REVOKED',
          error: 'Could not verify credential status -- failing closed',
        };
      }
    }

    // Migration credential claim extraction
    const isMigrationCredential = vcTypes?.includes(IDENTITY_MIGRATION_CREDENTIAL);
    let migrationClaims: MigrationCredentialClaims | undefined;
    if (isMigrationCredential) {
      const cs = payload.vc?.credentialSubject;
      if (
        cs?.previousDid &&
        cs?.oidcSubject &&
        cs?.migrationMethod &&
        cs?.oidcIssuer &&
        cs?.migratedAt
      ) {
        migrationClaims = {
          previousDid: cs.previousDid as string,
          oidcSubject: cs.oidcSubject as string,
          migrationMethod: cs.migrationMethod as string,
          oidcIssuer: cs.oidcIssuer as string,
          migratedAt: cs.migratedAt as string,
        };
      } else {
        return {
          valid: false,
          status: 'MALFORMED',
          error:
            'IdentityMigrationCredential missing required claims: previousDid, oidcSubject, migrationMethod, oidcIssuer, migratedAt',
        };
      }
    }

    const credential: DecodedCredential = {
      issuer: payload.iss,
      subject: payload.sub,
      issuedAt: new Date(iatMs ?? 0),
      expiresAt: new Date(expMs ?? 0),
      scope,
      credentialStatus: payload.vc?.credentialStatus
        ? {
            id: payload.vc.credentialStatus.id ?? '',
            type: payload.vc.credentialStatus.type ?? '',
            statusPurpose: payload.vc.credentialStatus.statusPurpose ?? '',
            statusListIndex: payload.vc.credentialStatus.statusListIndex ?? '',
            statusListCredential: payload.vc.credentialStatus.statusListCredential ?? '',
          }
        : undefined,
      vcTypes,
      delegationChain,
      migrationClaims,
    };

    return {
      valid: true,
      status: isMigrationCredential ? 'MIGRATION_DETECTED' : 'VALID',
      credential,
    };
  }

  /** Extract scope columns from a verified credential JWT. */
  extractScope(jwt: string): CredentialScope {
    const { payload } = decodeJwt(jwt);
    const scope = payload.vc?.credentialSubject?.scope;
    if (!scope) {
      throw new CredentialMalformedError("No 'scope' in credentialSubject");
    }
    return scope;
  }

  get cacheSize(): number {
    return this.cache.size;
  }

  get replayCacheSize(): number {
    return this.replayGuard.size;
  }

  clearReplayCache(): void {
    this.replayGuard.clear();
  }
}
