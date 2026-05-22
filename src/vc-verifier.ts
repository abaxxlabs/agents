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

/**
 * Agents++ — VC Verifier
 *
 * Validates agent credentials: signature, expiry, revocation, issuer chain.
 *
 * Identity stack: agents++ ships a self-contained identity implementation on
 * `node:crypto` (free tier). When an `IdSdkInstance` is injected — usually via
 * `connectIdSdkMcp()` from `@abaxxlabs/agents/id-sdk-mcp` — VcVerifier
 * delegates DID resolution, JWT signature verification, and StatusList 2021
 * lookup to the platform identity stack behind the MCP boundary. Without an
 * injected SDK, the verifier handles `did:key` locally and rejects non-`did:key`
 * DIDs with `DidResolutionFailedError`.
 *
 * agents++ and the platform identity stack are peer implementations of W3C
 * DID/VC/VP by deliberate design. agents++ does NOT import the id-sdk runtime
 * into the main package entry; the integration is opt-in via runtime injection
 * or the isolated MCP adapter subpath.
 */

import { parseDuration } from './config.js';
import { base58Decode } from './crypto/base58.js';
import type { RevocationStore } from './storage/types.js';
import type { CredentialScope } from './types/credential.js';
import {
  IDENTITY_MIGRATION_CREDENTIAL,
  type MigrationCredentialClaims,
} from './types/migration.js';
import { CredentialMalformedError, DidResolutionFailedError } from './errors/index.js';
import type { Did } from './types/domain.js';
import type { IdSdkInstance } from './types/id-sdk.js';
import type { VerifyOptions, VerificationResult, DecodedCredential } from './types/verification.js';

export type { VerifyOptions, VerificationResult, DecodedCredential } from './types/verification.js';
import { decodeJwt, verifyJwtSignature } from './jwt-utils.js';
import { isDelegatedScopeCredentialType } from './auth/credential-issuance.js';
import { DidCache } from './did-cache.js';
import { resolveDidKeyFallback } from './did-resolve.js';

export { decodeJwt, createJwt, verifyJwtSignature, type JwtHeader, type JwtPayload } from './jwt-utils.js';
export { DidCache } from './did-cache.js';
export { resolveDidKeyFallback, resolveDidKey } from './did-resolve.js';

export interface VcVerifierOptions {
  /**
   * Symmetric tolerance applied to VP timestamp checks only. Default: `'5s'`.
   *
   * Applied at VP `nbf`, VP `exp`, and VP JTI replay-cache TTL extension.
   * NOT applied to VC `nbf`/`exp` — credential timestamps are authoritative
   * business-level access control, not clock-sync artifacts.
   *
   * Maximum: 30 seconds. This is machine-to-machine auth at internet scale;
   * modern NTP keeps clocks within milliseconds, sub-second even cross-region.
   */
  clockSkew?: string;
  resolverCacheTtl?: string; // default: '5m'
  /** Enable jti-based credential replay protection. Default: true */
  replayProtection?: boolean;
  /** Max JTI cache entries before forced eviction. Default: 100_000 */
  maxReplayCacheSize?: number;
  /** Platform identity handle — enables full DID/VC/VP verification. */
  sdk?: IdSdkInstance;
  /** Pre-registered DID → publicKey map (used as a fallback when no SDK is injected). */
  knownKeys?: Map<string, Uint8Array>;
  /**
   * Pluggable revocation store — REQUIRED.
   *
   * Consumers must declare their revocation posture explicitly. There is no
   * default in-memory fallback: a missing store is a deployment-time error,
   * not a silent regression. For tests or single-instance demos that genuinely
   * want in-memory: `new InMemoryRevocationStore()`. For production:
   * Postgres (durable, cross-instance coherent) or SQLite (file-backed).
   */
  revocationStore: RevocationStore;
}

export interface VcVerifierTelemetrySink {
  revocationCheck(event: {
    source: 'local_store' | 'credential_status';
    credentialId?: string;
    outcome: 'not_revoked' | 'revoked' | 'suspended' | 'failed';
    error?: unknown;
  }): void;
}

export class VcVerifier {
  private cache: DidCache;
  private clockSkewMs: number;
  private knownKeys: Map<string, Uint8Array>;
  private sdk: IdSdkInstance | undefined;
  private replayProtection: boolean;
  private maxReplayCacheSize: number;
  private readonly revocationStore: RevocationStore;
  private telemetry?: VcVerifierTelemetrySink;
  /** Tracks seen JTIs → expiry timestamp (ms). Entries are lazily evicted. */
  private seenJtis = new Map<string, number>();
  private lastEviction = Date.now();
  private static readonly EVICTION_INTERVAL_MS = 60_000; // run eviction at most once per minute

  constructor(options: VcVerifierOptions) {
    this.cache = new DidCache(options.resolverCacheTtl ?? '5m');
    const MAX_CLOCK_SKEW_MS = 30 * 1_000;
    this.clockSkewMs = parseDuration(options.clockSkew ?? '5s');
    if (this.clockSkewMs <= 0) {
      throw new Error(
        'clockSkew must be greater than zero — zero tolerance causes false rejections under any clock drift',
      );
    }
    if (this.clockSkewMs > MAX_CLOCK_SKEW_MS) {
      throw new Error(
        'clockSkew exceeds maximum of 30 seconds — ' +
          'this is machine-to-machine auth; values beyond NTP-realistic drift extend VP lifetime, not clock tolerance',
      );
    }
    this.knownKeys = options.knownKeys ?? new Map();
    this.sdk = options.sdk;
    this.replayProtection = options.replayProtection ?? true;
    this.maxReplayCacheSize = options.maxReplayCacheSize ?? 100_000;
    this.revocationStore = options.revocationStore;
  }

  /**
   * Attach a best-effort operational telemetry sink.
   *
   * Revocation checks sit inside credential verification, below REST/MCP. This
   * additive hook lets hosted runtimes observe revoked/not-revoked/fail-closed
   * outcomes without exposing the raw credential JWT or changing verification
   * behavior for library consumers.
   */
  setTelemetrySink(sink: VcVerifierTelemetrySink | undefined): void {
    this.telemetry = sink;
  }

  private emitRevocationTelemetry(event: {
    source: 'local_store' | 'credential_status';
    credentialId?: string;
    outcome: 'not_revoked' | 'revoked' | 'suspended' | 'failed';
    error?: unknown;
  }): void {
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
   * Revoke a credential by its JTI. Throws on storage failure — callers must
   * treat rejection as a hard failure, never a silent continue.
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

  /**
   * Check whether a credential JTI has been revoked. Thin proxy over
   * `revocationStore.isRevoked()` — public so callers can verify revocation
   * state without reaching into the private store reference.
   */
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
    // Check cache first
    const cached = this.cache.get(brandedDid);
    if (cached) return cached;

    // Check known keys
    const known = this.knownKeys.get(did);
    if (known) {
      this.cache.set(brandedDid, known);
      return known;
    }

    // Use platform DID resolution if available.
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
          // Ed25519 JWK → raw 32-byte key
          const xBytes = Buffer.from(vm.publicKeyJwk.x, 'base64url');
          publicKey = new Uint8Array(xBytes);
        } else if (vm.publicKeyMultibase) {
          // Multibase-encoded key (base58btc)
          const encoded = vm.publicKeyMultibase.slice(1); // remove 'z' prefix
          publicKey = base58Decode(encoded);
          // Strip multicodec prefix if present (0xed01 for Ed25519)
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

    // Fallback: try did:key resolution without SDK
    if (did.startsWith('did:key:z')) {
      const pk = resolveDidKeyFallback(brandedDid);
      this.cache.set(brandedDid, pk);
      return pk;
    }

    throw new DidResolutionFailedError(
      did,
      `Cannot resolve ${did} — no platform DID resolver available and not a did:key`,
    );
  }

  /**
   * Verify a credential JWT — signature, expiry, revocation, scope structure.
   * Uses the injected platform VC verifier when available for full verification.
   *
   * @param jwt    The credential JWT to verify.
   * @param options  Optional verification controls. See VerifyOptions in types.ts.
   *
   * Security: pass `options.expectedSubject` whenever the requesting agent's
   * DID is known. Without it, a valid VC issued for agent-A can be replayed
   * by agent-B (confused-deputy attack). `skipScopeCheck` is for
   * IdentityBindingCredentials only — never set it for scope-bearing
   * capability credentials.
   */
  async verify(jwt: string, options: VerifyOptions = {}): Promise<VerificationResult> {
    // 1. Decode (lightweight, no SDK needed)
    let decoded: ReturnType<typeof decodeJwt>;
    try {
      decoded = decodeJwt(jwt);
    } catch {
      return { valid: false, status: 'MALFORMED', error: 'Failed to decode JWT' };
    }

    const { payload } = decoded;

    // 1b. VP detection and unwrapping.
    //
    // A Verifiable Presentation wraps one or more VCs. When we receive a VP:
    //   1. Verify the VP's own signature (the presenter/agent signed it)
    //   2. Check VP replay protection (nonce-based, per-presentation)
    //   3. Check VP audience binding
    //   4. Extract the inner VC and verify it recursively (without replay)
    //
    // This separation is why VCs are reusable and VPs are single-use.
    const vpClaim = payload.vp as { type?: string[]; verifiableCredential?: string[] } | undefined;
    const isVP = vpClaim?.type?.includes?.('VerifiablePresentation');
    if (isVP) {
      // VP must have an issuer (the presenting agent's DID)
      if (!payload.iss) {
        return { valid: false, status: 'MALFORMED', error: 'VP missing issuer (iss) claim' };
      }

      // Verify VP signature — the agent that created the presentation signed it
      let vpSigValid: boolean;
      try {
        const publicKey = await this.resolvePublicKey(payload.iss);
        vpSigValid = await verifyJwtSignature(jwt, publicKey);
      } catch (err) {
        if (err instanceof DidResolutionFailedError) {
          return { valid: false, status: 'UNKNOWN_ISSUER', error: `VP issuer: ${err.message}` };
        }
        throw err;
      }
      if (!vpSigValid) {
        return {
          valid: false,
          status: 'INVALID_SIGNATURE',
          error: 'VP signature verification failed',
        };
      }

      // VP audience binding — fail-closed: if expectedAudience is set, the VP
      // MUST have a matching aud claim. Missing aud is rejected, not skipped.
      if (options.expectedAudience) {
        if (!payload.aud) {
          return {
            valid: false,
            status: 'WRONG_AUDIENCE',
            error: `VP missing audience claim, expected ${options.expectedAudience}`,
          };
        }
        const audClaim = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
        if (!audClaim.includes(options.expectedAudience)) {
          return {
            valid: false,
            status: 'WRONG_AUDIENCE',
            error: `VP audience mismatch: expected ${options.expectedAudience}, got ${audClaim.join(', ')}`,
          };
        }
      }

      // VP nbf — reject presentations not yet valid (symmetric with VC nbf check).
      // VPs are typically short-lived, but a VP with nbf in the future should
      // not be accepted — the presenter may be trying to pre-stage a replay.
      const vpNbf = payload.nbf ?? payload.iat;
      if (vpNbf) {
        const vpNbfMs = vpNbf * 1000;
        if (Date.now() < vpNbfMs - this.clockSkewMs) {
          return {
            valid: false,
            status: 'MALFORMED',
            error: `VP not valid until ${new Date(vpNbfMs).toISOString()}`,
          };
        }
      }

      // VP expiry
      if (payload.exp) {
        const expMs = payload.exp * 1000;
        if (Date.now() > expMs + this.clockSkewMs) {
          return {
            valid: false,
            status: 'EXPIRED',
            error: `VP expired at ${new Date(expMs).toISOString()}`,
          };
        }
      }

      // VP replay protection — nonce (JTI) must not have been seen before.
      // maxReplayCacheSize (default 100K) prevents unbounded memory growth
      // under sustained load. When at capacity, force eviction then drop oldest.
      if (this.replayProtection && payload.jti) {
        if (this.seenJtis.size >= this.maxReplayCacheSize) {
          this.evictExpiredJtis(true);
        } else {
          this.evictExpiredJtis();
        }
        if (this.seenJtis.has(payload.jti)) {
          return {
            valid: false,
            status: 'REPLAYED',
            error: `Presentation nonce ${payload.jti} has already been used`,
          };
        }
        // If still at capacity after eviction, drop oldest entry
        if (this.seenJtis.size >= this.maxReplayCacheSize) {
          const oldest = this.seenJtis.keys().next().value;
          if (oldest !== undefined) this.seenJtis.delete(oldest);
        }
        const expiresAtMs = payload.exp
          ? payload.exp * 1000 + this.clockSkewMs
          : Date.now() + 5 * 60 * 1000;
        this.seenJtis.set(payload.jti, expiresAtMs);
      }

      // Extract inner VC(s)
      const innerVCs = vpClaim!.verifiableCredential;
      if (!Array.isArray(innerVCs) || innerVCs.length === 0) {
        return {
          valid: false,
          status: 'MALFORMED',
          error: 'VP contains no verifiable credentials',
        };
      }

      // Scan for IdentityMigrationCredential before processing scope VCs.
      // Migration credentials are detected by type and returned separately so
      // the caller (scope engine) can process the migration before evaluating
      // scope.
      for (const innerJwt of innerVCs) {
        try {
          const innerDecoded = decodeJwt(innerJwt);
          const innerTypes: string[] | undefined = innerDecoded.payload.vc?.type;
          if (Array.isArray(innerTypes) && innerTypes.includes(IDENTITY_MIGRATION_CREDENTIAL)) {
            // Verify the migration credential with skipScopeCheck (no scope.columns).
            const migrationResult = await this.verify(innerJwt, {
              skipScopeCheck: true,
              expectedSubject: options.expectedSubject ?? payload.iss,
              expectedAudience: options.expectedAudience,
            });
            if (migrationResult.valid && migrationResult.credential?.migrationClaims) {
              return {
                valid: true,
                status: 'MIGRATION_DETECTED',
                credential: migrationResult.credential,
              };
            }
            // If migration credential is invalid, fall through to scope VC processing.
            // A bad migration credential should not block normal operations.
          }
        } catch {
          // Malformed inner VC — skip, continue to scope VC
        }
      }

      // Filter out migration-typed VCs before scope processing. A migration
      // credential that failed verification must not fall through to the scope
      // path where it could be accepted as a normal scope VC.
      const scopeVCs = innerVCs.filter((jwt: string) => {
        try {
          const d = decodeJwt(jwt);
          const t: string[] | undefined = d.payload.vc?.type;
          return !Array.isArray(t) || !t.includes(IDENTITY_MIGRATION_CREDENTIAL);
        } catch {
          return true;
        }
      });

      if (scopeVCs.length === 0) {
        return {
          valid: false,
          status: 'MALFORMED',
          error: 'VP contains no scope credentials (only migration credentials)',
        };
      }

      // Verify the first scope VC. The presenter's DID becomes the expected
      // subject (the agent presenting the VP must be the credential's subject).
      const innerResult = await this.verify(scopeVCs[0], {
        ...options,
        expectedSubject: options.expectedSubject ?? payload.iss,
      });
      return innerResult;
    }

    // ── Raw VC verification (below) ─────────────────────────────────

    // 2. Check required fields
    if (!payload.iss) {
      return { valid: false, status: 'MALFORMED', error: 'Missing issuer (iss) claim' };
    }
    if (!payload.sub) {
      return { valid: false, status: 'MALFORMED', error: 'Missing subject (sub) claim' };
    }

    // 3. Check scope claim — skipped for IdentityBindingCredentials and other
    //    VC types that carry no scope.columns by design (options.skipScopeCheck).
    //    For all capability credentials, scope.columns is required.
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

    // 4a. Check nbf (not before) — VC timestamps are authoritative, no clockSkew tolerance.
    const now = Date.now();
    const nbf = payload.nbf ?? payload.iat;
    if (nbf) {
      const nbfMs = nbf * 1000;
      if (now < nbfMs) {
        return {
          valid: false,
          status: 'MALFORMED',
          error: `Credential not valid until ${new Date(nbfMs).toISOString()}`,
        };
      }
    }

    // 4b. Check expiry — authoritative, no clockSkew tolerance.
    if (payload.exp) {
      const expMs = payload.exp * 1000;
      if (now > expMs) {
        return {
          valid: false,
          status: 'EXPIRED',
          error: `Credential expired at ${new Date(expMs).toISOString()}`,
        };
      }
    }

    // 5. Verify signature
    let sigValid: boolean;
    if (this.sdk) {
      // Use platform verification for all DID methods when an SDK handle exists.
      try {
        sigValid = await this.sdk.vc.verifyJWT(jwt);
      } catch {
        sigValid = false;
      }
    } else {
      // Fallback: manual Ed25519 verification
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

    // 5b. Subject binding check — prevents confused-deputy attacks. After the
    //     signature is confirmed valid, assert that the credential was issued
    //     TO the agent making this request. Without this check, agent-B can
    //     present a cryptographically valid credential that was issued for
    //     agent-A and pass signature verification.
    //
    //     Returns WRONG_SUBJECT (not INVALID_SIGNATURE): the signature IS
    //     valid, the credential was simply issued for a different agent.
    //     Using INVALID_SIGNATURE here would send callers debugging key
    //     rotation instead of authorization.
    if (options.expectedSubject && payload.sub !== options.expectedSubject) {
      return {
        valid: false,
        status: 'WRONG_SUBJECT',
        error: `Credential subject mismatch: expected ${options.expectedSubject}, got ${payload.sub}`,
      };
    }

    // 5b2. Audience binding check — prevents VP replay across servers.
    //      Without this, a VP captured from Server X can be replayed to Server Y.
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

    // 5c. Replay protection — handled at the VP layer (top of verify()).
    // Raw VCs are NOT replay-tracked. They are reusable credentials, valid
    // until expiry or revocation. Per-query freshness comes from the VP
    // wrapper, which gets a unique nonce on every presentation.

    // 5d. Revocation check. The injected store acquires row-level locks in
    // its Postgres/SQLite adapters to close the concurrent revoke+verify race.
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

    // 7. Build decoded credential — structural checks run before chain revocation I/O
    // to prevent resource amplification from malformed credentials.
    const rawVcType = payload.vc?.type;
    const vcTypes: string[] | undefined = Array.isArray(rawVcType)
      ? rawVcType
      : typeof rawVcType === 'string' ? [rawVcType] : undefined;
    // DWN-aligned: delegationChain is a top-level JWT claim, not inside
    // credentialSubject. Matches abaxx-id-go permissions-grant.json structure.
    const delegationChain: string[] | undefined = Array.isArray(payload.delegationChain)
      ? payload.delegationChain
      : undefined;
    if (delegationChain !== undefined && delegationChain.length === 0) {
      return {
        valid: false,
        status: 'MALFORMED',
        error: 'Credential has empty delegationChain — a delegated credential must have at least one ancestor.',
      };
    }
    const isDelegatedType = vcTypes !== undefined && isDelegatedScopeCredentialType(vcTypes);
    // Require at least one string JWT entry; non-string entries are filtered in the walk
    // and a chain of only non-strings would silently pass as non-empty without this check.
    const hasChain = delegationChain !== undefined && delegationChain.some((e): e is string => typeof e === 'string');
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

    const chainResult = await this.checkDelegationChainRevocation(payload.delegationChain);
    if (chainResult) return chainResult;

    // 6. Check revocation status (if SDK available and credential has status)
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
        // Status check failed — fail closed (reject)
        this.emitRevocationTelemetry({
          source: 'credential_status',
          credentialId: payload.vc.credentialStatus.id,
          outcome: 'failed',
        });
        return {
          valid: false,
          status: 'REVOKED',
          error: 'Could not verify credential status — failing closed',
        };
      }
    }

    // Extract migration credential claims when the VC type is
    // IdentityMigrationCredential. These are passed to the scope engine
    // for the migration detection pre-step.
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
      issuedAt: new Date((payload.iat ?? 0) * 1000),
      expiresAt: new Date((payload.exp ?? 0) * 1000),
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
    return this.seenJtis.size;
  }

  clearReplayCache(): void {
    this.seenJtis.clear();
  }

  /** Strict resolver: knownKeys or SDK only. No did:key fallback — self-asserting DIDs are not trusted delegators. */
  private async resolveRegisteredIssuerKey(did: string): Promise<Uint8Array | null> {
    const known = this.knownKeys.get(did);
    if (known) return known;
    if (!this.sdk) return null;
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
      const vm = doc?.verificationMethod?.[0];
      if (!vm) return null;
      if (vm.publicKeyJwk) {
        return new Uint8Array(Buffer.from(vm.publicKeyJwk.x, 'base64url'));
      }
      if (vm.publicKeyMultibase) {
        const encoded = vm.publicKeyMultibase.slice(1);
        const pk = base58Decode(encoded);
        return pk[0] === 0xed && pk[1] === 0x01 ? pk.slice(2) : pk;
      }
      return null;
    } catch {
      return null;
    }
  }

  /** Reject when any ancestor JTI in delegationChain is revoked. Depth-capped against hostile input. */
  private async checkDelegationChainRevocation(
    rootChain: unknown,
  ): Promise<VerificationResult | undefined> {
    if (!Array.isArray(rootChain) || rootChain.length === 0) return undefined;

    const MAX_CHAIN_DEPTH = 10;
    let depth = 0;
    let cursor: string[] = rootChain.filter((j): j is string => typeof j === 'string');

    while (cursor.length > 0) {
      if (++depth > MAX_CHAIN_DEPTH) {
        return {
          valid: false,
          status: 'MALFORMED',
          error: `Delegation chain exceeds maximum depth of ${MAX_CHAIN_DEPTH}`,
        };
      }
      const next: string[] = [];
      for (const ancestorJwt of cursor) {
        let ancestorPayload: ReturnType<typeof decodeJwt>['payload'];
        try {
          ancestorPayload = decodeJwt(ancestorJwt).payload;
        } catch {
          return {
            valid: false,
            status: 'MALFORMED',
            error: 'Delegation chain contains malformed JWT',
          };
        }

        // Verify signature against a registered issuer before trusting any claim.
        if (!ancestorPayload.iss) {
          return {
            valid: false,
            status: 'MALFORMED',
            error: 'Delegation chain ancestor missing issuer (iss) claim',
          };
        }
        const ancestorKey = await this.resolveRegisteredIssuerKey(ancestorPayload.iss);
        if (!ancestorKey) {
          return {
            valid: false,
            status: 'UNKNOWN_ISSUER',
            error: 'Delegation chain ancestor issuer not registered',
          };
        }
        if (!await verifyJwtSignature(ancestorJwt, ancestorKey)) {
          return {
            valid: false,
            status: 'INVALID_SIGNATURE',
            error: 'Delegation chain ancestor signature invalid',
          };
        }

        const rawAncestorType = ancestorPayload.vc?.type;
        const ancestorVcType: unknown[] = Array.isArray(rawAncestorType)
          ? rawAncestorType
          : typeof rawAncestorType === 'string' ? [rawAncestorType] : [];
        if (isDelegatedScopeCredentialType(ancestorVcType)) {
          return {
            valid: false,
            status: 'MALFORMED',
            error: 'Delegation chain contains a re-delegated credential.',
          };
        }
        if (ancestorPayload.jti) {
          let ancestorRevoked: boolean;
          try {
            ancestorRevoked = await this.revocationStore.isRevoked(ancestorPayload.jti);
          } catch (err) {
            this.emitRevocationTelemetry({
              source: 'local_store',
              credentialId: ancestorPayload.jti,
              outcome: 'failed',
              error: err,
            });
            throw err;
          }
          this.emitRevocationTelemetry({
            source: 'local_store',
            credentialId: ancestorPayload.jti,
            outcome: ancestorRevoked ? 'revoked' : 'not_revoked',
          });
          if (ancestorRevoked) {
            return {
              valid: false,
              status: 'REVOKED',
              error: `Delegation chain credential ${ancestorPayload.jti} has been revoked`,
            };
          }
        }
        if (Array.isArray(ancestorPayload.delegationChain)) {
          for (const inner of ancestorPayload.delegationChain) {
            if (typeof inner === 'string') next.push(inner);
          }
        }
      }
      cursor = next;
    }
    return undefined;
  }

  private evictExpiredJtis(force = false): void {
    const now = Date.now();
    if (!force && now - this.lastEviction < VcVerifier.EVICTION_INTERVAL_MS) return;
    this.lastEviction = now;
    for (const [jti, expiresAt] of this.seenJtis) {
      if (now > expiresAt) {
        this.seenJtis.delete(jti);
      }
    }
  }
}

