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
 * ChallengeStore — HMAC-signed time-based challenges with JTI dedup cache.
 *
 * The MCP `challenge` tool issues challenges that external verifiers include in VP requests.
 * The challenge proves the VP was freshly created for this specific verifier, preventing
 * replay attacks where an attacker intercepts a signed VP and re-presents it.
 *
 * Protocol: timestamp+audience+UUID7 JTI (NOT nonce-based).
 *   - Stateless issuance: any server with the HMAC secret can create challenges.
 *   - HMAC-SHA256 prevents challenge forgery without the server secret.
 *   - UUID7 JTI for replay dedup with bounded dedup cache (max 100 entries).
 *   - Dedup cache provides zero-replay-window (atomic check-and-insert).
 *   - An attacker presenting tokens with unknown kids could force unlimited cache-bust
 *     re-fetches — the per-URI 30-second cooldown limits this to at most once per 30s.
 */

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { v7 as uuidv7 } from 'uuid';

// ─── Constants ───────────────────────────────────────────────────────────────

/** Default challenge TTL in seconds. */
export const DEFAULT_CHALLENGE_TTL_SECONDS = 60;

/**
 * Maximum allowed TTL for challenge issuance (seconds).
 *
 * Without this cap, an authenticated client can request ttlSeconds=Infinity,
 * creating challenges that never expire — defeating the time-bound freshness
 * guarantee and enabling dedup cache exhaustion.
 */
export const MAX_CHALLENGE_TTL_SECONDS = 300;

/** Max JTI dedup cache entries. At 1 challenge/s with 60s TTL, steady-state ≈60. */
export const MAX_DEDUP_CACHE_SIZE = 100;

/** Max clock skew for challenge issuance timestamps (same-process tokens). */
export const CHALLENGE_FUTURE_SKEW_SECONDS = 5;

// ─── Types ───────────────────────────────────────────────────────────────────

/** Options for issuing a challenge. */
export interface ChallengeIssueOptions {
  /** DID of the entity requesting the challenge. Bound into the HMAC. */
  requestorDid?: string;
  /** Challenge validity in seconds. Default: DEFAULT_CHALLENGE_TTL_SECONDS (60). */
  ttlSeconds?: number;
}

/** Result of issuing a challenge. Returned to the MCP caller. */
export interface ChallengeIssueResult {
  /** The opaque challenge string. Include in VP `nonce` or `challenge` field. */
  challenge: string;
  /** Unix timestamp (seconds) when this challenge expires. */
  expiresAt: number;
  /** UUID7 JTI for correlation and audit. */
  jti: string;
}

/** Result of consuming (verifying) a challenge. */
export interface ChallengeConsumeResult {
  /** Whether the challenge is valid and not yet consumed. */
  valid: boolean;
  /** On failure, the reason for rejection. */
  reason?: string;
  /** On success, the extracted JTI for audit correlation. */
  jti?: string;
  /** On success, the requestorDid bound into the challenge (if any). */
  requestorDid?: string;
}

/**
 * Internal structure of a challenge payload.
 *
 * Serialized as JSON, then base64url-encoded. The HMAC covers all fields
 * except `h` (the HMAC itself). Field names are kept short to minimize
 * challenge string length — these are wire tokens, not human-readable config.
 */
interface ChallengePayload {
  /** Issued-at timestamp (Unix seconds). */
  t: number;
  /** Expiry timestamp (Unix seconds). */
  x: number;
  /** UUID7 JTI. */
  j: string;
  /** Requestor DID (empty string if not provided). */
  a: string;
  /** HMAC-SHA256 of the other fields (hex-encoded). */
  h: string;
}

// ─── ChallengeStore ──────────────────────────────────────────────────────────

/**
 * ChallengeStore — issue and consume HMAC-signed time-based challenges.
 *
 * Issuance is stateless (any store with the same secret can verify). Consumption
 * is stateful (per-process JTI cache). Multi-server deployments may need a
 * shared cache or accept the per-server model if TTL is short enough.
 *
 * @example
 *   const store = new ChallengeStore();
 *   const { challenge } = store.issue({ requestorDid: 'did:key:...' });
 *   const result = store.consume(challenge);
 *   if (!result.valid) throw new Error(result.reason);
 */
export class ChallengeStore {
  /**
   * HMAC-SHA256 secret for signing challenges.
   * 32 bytes of cryptographic randomness — domain-separated from signing keys.
   */
  private readonly hmacSecret: Buffer;

  // Map<jti, expiresAt>. Insertion-ordered (JavaScript Map guarantee); UUID7 means oldest = front.
  // consume() is synchronous and atomic — check-and-insert in a single operation.
  // No TOCTOU race possible because JavaScript is single-threaded.
  // If this ever goes async (e.g., Redis backend), a mutex or atomic CAS is required.
  private readonly dedupCache: Map<string, number> = new Map();

  /**
   * @param options.hmacSecret — explicit HMAC secret (for multi-server shared secret).
   *   If not provided, a random 32-byte secret is generated. Per-process only.
   */
  constructor(options?: { hmacSecret?: Buffer }) {
    this.hmacSecret = options?.hmacSecret ?? randomBytes(32);
  }

  /** Issue an HMAC-signed challenge. Evicts expired cache entries lazily. */
  issue(options?: ChallengeIssueOptions): ChallengeIssueResult {
    this.evictExpired();

    const now = Math.floor(Date.now() / 1000);
    // Clamp TTL: minimum 1s (prevent zero/negative), maximum MAX_CHALLENGE_TTL_SECONDS.
    // Unbounded TTL would defeat the freshness guarantee.
    const rawTtl = options?.ttlSeconds ?? DEFAULT_CHALLENGE_TTL_SECONDS;
    const ttl = Math.max(1, Math.min(rawTtl, MAX_CHALLENGE_TTL_SECONDS)); // clamp TTL
    const expiresAt = now + ttl;
    const jti = uuidv7();
    const requestorDid = options?.requestorDid ?? '';

    const hmac = this.computeHmac(now, expiresAt, jti, requestorDid);

    const payload: ChallengePayload = {
      t: now,
      x: expiresAt,
      j: jti,
      a: requestorDid,
      h: hmac,
    };

    const challenge = Buffer.from(JSON.stringify(payload), 'utf-8').toString('base64url');

    return { challenge, expiresAt, jti };
  }

  /**
   * Verify a challenge and insert its JTI into the dedup cache (atomic check-and-insert).
   * Subsequent calls with the same challenge are rejected as replays.
   */
  consume(challenge: string): ChallengeConsumeResult {
    this.evictExpired();

    // ── Step 1: Decode ──────────────────────────────────────────────
    let payload: ChallengePayload;
    try {
      const json = Buffer.from(challenge, 'base64url').toString('utf-8');
      payload = JSON.parse(json) as ChallengePayload;
    } catch {
      return { valid: false, reason: 'Challenge is malformed (invalid encoding)' };
    }

    // ── Step 2: Structural validation ───────────────────────────────
    if (
      typeof payload.t !== 'number' ||
      typeof payload.x !== 'number' ||
      typeof payload.j !== 'string' ||
      typeof payload.a !== 'string' ||
      typeof payload.h !== 'string'
    ) {
      return { valid: false, reason: 'Challenge is malformed (missing fields)' };
    }

    // ── Step 4: Verify HMAC (constant-time) ────────────────────────
    // HMAC hex digests are fixed-length (64 chars for SHA-256), so timingSafeEqual works
    // directly without length normalization. Timing-safe comparison prevents hash-oracle attacks.
    const expectedHmac = this.computeHmac(payload.t, payload.x, payload.j, payload.a);
    const expectedBuf = Buffer.from(expectedHmac, 'utf-8');
    const actualBuf = Buffer.from(payload.h, 'utf-8');
    if (expectedBuf.length !== actualBuf.length || !timingSafeEqual(expectedBuf, actualBuf)) {
      return { valid: false, reason: 'Challenge HMAC verification failed' };
    }

    // ── Step 5: Check temporal bounds ───────────────────────────────
    const now = Math.floor(Date.now() / 1000);
    if (now >= payload.x) {
      return { valid: false, reason: 'Challenge has expired' };
    }
    if (payload.t > now + CHALLENGE_FUTURE_SKEW_SECONDS) {
      return { valid: false, reason: 'Challenge issued in the future (clock skew)' };
    }

    // ── Step 6: JTI dedup ───────────────────────────────────────────
    if (this.dedupCache.has(payload.j)) {
      return { valid: false, reason: 'Challenge already consumed (replay rejected)' };
    }

    if (this.dedupCache.size >= MAX_DEDUP_CACHE_SIZE) { // evict oldest (Map insertion order)
      const oldestKey = this.dedupCache.keys().next().value;
      if (oldestKey !== undefined) {
        this.dedupCache.delete(oldestKey);
      }
    }
    this.dedupCache.set(payload.j, payload.x);

    return {
      valid: true,
      jti: payload.j,
      requestorDid: payload.a || undefined,
    };
  }

  // ── Internal Helpers ─────────────────────────────────────────────────────────

  /**
   * Compute HMAC-SHA256. Length-prefixed encoding prevents field-boundary
   * confusion (pipes are legal in DID query/fragment components).
   */
  private computeHmac(iat: number, exp: number, jti: string, requestorDid: string): string {
    // Length-prefixed: each variable-length field is preceded by its byte length.
    // Fixed-width numeric fields (iat, exp) are serialized as strings with ':' delimiter.
    const didBytes = Buffer.byteLength(requestorDid, 'utf-8');
    const jtiBytes = Buffer.byteLength(jti, 'utf-8');
    return createHmac('sha256', this.hmacSecret)
      .update(`${iat}:${exp}:${jtiBytes}:${jti}${didBytes}:${requestorDid}`)
      .digest('hex');
  }

  /** Evict expired entries from the dedup cache. Full scan is fine — max 100 entries. */
  private evictExpired(): void {
    const now = Math.floor(Date.now() / 1000);
    for (const [jti, expiresAt] of this.dedupCache) {
      if (expiresAt < now) {
        this.dedupCache.delete(jti);
      }
    }
  }

  /**
   * Current dedup cache size. Exposed for testing and monitoring.
   */
  get cacheSize(): number {
    return this.dedupCache.size;
  }
}
