import type { VerifyOptions, VerificationResult } from '#types/index.js';
import type { JwtPayload } from '#crypto/jwt.js';
import { decodeJwt, verifyJwtSignature } from '#crypto/jwt.js';
import { IDENTITY_MIGRATION_CREDENTIAL } from '#types/index.js';
import { DidResolutionFailedError } from '#errors/index.js';

export class ReplayGuard {
  private seenJtis = new Map<string, number>();
  private lastEviction = Date.now();
  private static readonly EVICTION_INTERVAL_MS = 60_000;

  constructor(
    private readonly maxCacheSize: number,
    private readonly enabled: boolean,
  ) {}

  get size(): number {
    return this.seenJtis.size;
  }

  clear(): void {
    this.seenJtis.clear();
  }

  /** @returns true if the JTI is a replay (already seen), false if fresh. */
  checkAndRecord(jti: string, expiresAtMs: number): boolean {
    if (!this.enabled) return false;

    if (this.seenJtis.size >= this.maxCacheSize) {
      this.evict(true);
    } else {
      this.evict();
    }

    if (this.seenJtis.has(jti)) return true;

    if (this.seenJtis.size >= this.maxCacheSize) {
      const oldest = this.seenJtis.keys().next().value;
      if (oldest !== undefined) this.seenJtis.delete(oldest);
    }

    this.seenJtis.set(jti, expiresAtMs);
    return false;
  }

  private evict(force = false): void {
    const now = Date.now();
    if (!force && now - this.lastEviction < ReplayGuard.EVICTION_INTERVAL_MS) return;
    this.lastEviction = now;
    for (const [jti, expiresAt] of this.seenJtis) {
      if (now > expiresAt) {
        this.seenJtis.delete(jti);
      }
    }
  }
}

export interface VpVerificationDeps {
  clockSkewMs: number;
  replayGuard: ReplayGuard;
  resolvePublicKey(did: string): Promise<Uint8Array>;
  verifyInnerCredential(jwt: string, options: VerifyOptions): Promise<VerificationResult>;
}

export async function verifyPresentation(
  jwt: string,
  payload: JwtPayload,
  vpClaim: { type?: string[]; verifiableCredential?: string[] },
  options: VerifyOptions,
  deps: VpVerificationDeps,
): Promise<VerificationResult> {
  if (!payload.iss) {
    return { valid: false, status: 'MALFORMED', error: 'VP missing issuer (iss) claim' };
  }

  let vpSigValid: boolean;
  try {
    const publicKey = await deps.resolvePublicKey(payload.iss);
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

  const vpNbf = payload.nbf ?? payload.iat;
  if (vpNbf) {
    const vpNbfMs = vpNbf * 1000;
    if (Date.now() < vpNbfMs - deps.clockSkewMs) {
      return {
        valid: false,
        status: 'MALFORMED',
        error: `VP not valid until ${new Date(vpNbfMs).toISOString()}`,
      };
    }
  }

  if (payload.exp) {
    const expMs = payload.exp * 1000;
    if (Date.now() > expMs + deps.clockSkewMs) {
      return {
        valid: false,
        status: 'EXPIRED',
        error: `VP expired at ${new Date(expMs).toISOString()}`,
      };
    }
  }

  if (payload.jti) {
    const expiresAtMs = payload.exp
      ? payload.exp * 1000 + deps.clockSkewMs
      : Date.now() + 5 * 60 * 1000;
    if (deps.replayGuard.checkAndRecord(payload.jti, expiresAtMs)) {
      return {
        valid: false,
        status: 'REPLAYED',
        error: `Presentation nonce ${payload.jti} has already been used`,
      };
    }
  }

  const innerVCs = vpClaim.verifiableCredential;
  if (!Array.isArray(innerVCs) || innerVCs.length === 0) {
    return {
      valid: false,
      status: 'MALFORMED',
      error: 'VP contains no verifiable credentials',
    };
  }

  for (const innerJwt of innerVCs) {
    try {
      const innerDecoded = decodeJwt(innerJwt);
      const innerTypes: string[] | undefined = innerDecoded.payload.vc?.type;
      if (Array.isArray(innerTypes) && innerTypes.includes(IDENTITY_MIGRATION_CREDENTIAL)) {
        const migrationResult = await deps.verifyInnerCredential(innerJwt, {
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
      }
    } catch {
    }
  }

  const scopeVCs = innerVCs.filter((innerJwt: string) => {
    try {
      const d = decodeJwt(innerJwt);
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

  const innerResult = await deps.verifyInnerCredential(scopeVCs[0], {
    ...options,
    expectedSubject: options.expectedSubject ?? payload.iss,
  });
  return innerResult;
}
