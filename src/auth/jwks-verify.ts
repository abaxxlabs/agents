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
 * JWKS-based id_token signature verification.
 *
 * An unverified id_token is just base64-encoded JSON — anyone can forge claims in one.
 * Signature verification against the provider's JWKS is what makes identity claims trustworthy.
 *
 * Supported algorithms (covers all major OIDC providers):
 *   RS256, RS384, RS512  — RSA PKCS#1 v1.5 (Google, Azure, Okta, most generic providers)
 *   PS256, PS384, PS512  — RSA-PSS (FAPI-compliant providers)
 *   ES256, ES384, ES512  — ECDSA (Cloudflare Access, newer providers)
 *   EdDSA (Ed25519)      — AbaxxOne, did:key-based systems
 *
 * JWKS caching: module-level, 1-hour TTL per jwks_uri.
 *   On kid mismatch: automatic cache-bust and one retry (handles key rotation events).
 *   An attacker presenting tokens with unknown kids could force unlimited JWKS re-fetches
 *   (cache-bust amplification) — a per-URI 30-second cooldown limits this.
 */

import {
  createPublicKey,
  createVerify,
  verify as cryptoVerify,
  constants,
  type JsonWebKey,
} from 'node:crypto';
import { AuthUnavailableError } from '../errors.js';

// Only accept algorithms that major OIDC providers actually use. Prevents the "none" algorithm
// bypass and symmetric-key confusion attacks (e.g. alg:"HS256" with the JWKS public key used
// as an HMAC secret) and other algorithm-substitution attacks.
const ALLOWED_ALGS = new Set([
  'RS256',
  'RS384',
  'RS512',
  'PS256',
  'PS384',
  'PS512',
  'ES256',
  'ES384',
  'ES512',
  'EdDSA',
]);

/** 1 hour — matches the OIDC discovery document cache TTL. */
const JWKS_CACHE_TTL_MS = 60 * 60 * 1000;

interface JwksCacheEntry {
  keys: Record<string, unknown>[];
  cachedAt: number;
}

/** Shared across all provider instances in the process. */
const jwksCache = new Map<string, JwksCacheEntry>();

async function fetchJwks(jwksUri: string, bustCache = false): Promise<Record<string, unknown>[]> {
  const now = Date.now();
  if (!bustCache) {
    const cached = jwksCache.get(jwksUri);
    if (cached && now - cached.cachedAt < JWKS_CACHE_TTL_MS) {
      return cached.keys;
    }
  }

  let doc: unknown;
  try {
    // 5-second timeout prevents a hung JWKS endpoint from blocking the auth flow indefinitely.
    const res = await fetch(jwksUri, { signal: AbortSignal.timeout(5000) });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    doc = await res.json();
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'network error';
    throw new AuthUnavailableError(`JWKS fetch failed for ${jwksUri}: ${message}`);
  }

  const docKeys = (doc as { keys?: unknown } | null)?.keys;
  const keys: Record<string, unknown>[] = Array.isArray(docKeys)
    ? (docKeys as Record<string, unknown>[])
    : [];
  jwksCache.set(jwksUri, { keys, cachedAt: now });
  return keys;
}

// Per-URI cooldown prevents cache-bust amplification (unknown kids forcing unlimited re-fetches).
const jwksCacheBustCooldown = new Map<string, number>();
const JWKS_BUST_COOLDOWN_MS = 30_000;

// ─── Key Selection ────────────────────────────────────────────────────────────

/**
 * Find the JWKS key for this JWT. If kid present: exact match. If no kid: match by alg/kty.
 * Handles MockOidcServer JWTs (JWKS has kid, JWT doesn't) via the alg/kty fallback.
 */
function findKey(
  keys: Record<string, unknown>[],
  kid: string | undefined,
  alg: string,
): Record<string, unknown> | undefined {
  if (kid) {
    return keys.find((k) => k.kid === kid);
  }
  const kty = algToKty(alg);
  return keys.find((k) => (!k.alg || k.alg === alg) && (!kty || k.kty === kty));
}

function algToKty(alg: string): string | undefined {
  if (alg.startsWith('RS') || alg.startsWith('PS')) return 'RSA';
  if (alg.startsWith('ES')) return 'EC';
  if (alg === 'EdDSA') return 'OKP';
  return undefined;
}

// ─── Signature Verification ───────────────────────────────────────────────────

/**
 * Verify a JWT's signature using the appropriate algorithm.
 * Returns true on valid signature, false on invalid. Does not throw on invalid.
 */
function verifySignature(
  alg: string,
  signingInput: string,
  publicKey: ReturnType<typeof createPublicKey>,
  signature: Buffer,
): boolean {
  const data = Buffer.from(signingInput);
  try {
    if (alg === 'EdDSA') {
      // Ed25519/Ed448: pass null as algorithm (no separate digest step)
      return cryptoVerify(null, data, publicKey, signature);
    }

    if (alg.startsWith('PS')) {
      // RSA-PSS: requires explicit padding options
      return cryptoVerify(
        algToHash(alg),
        data,
        {
          key: publicKey,
          padding: constants.RSA_PKCS1_PSS_PADDING,
          saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
        },
        signature,
      );
    }

    // RS* (RSA PKCS#1 v1.5) and ES* (ECDSA): hash + key type inferred from key
    const verifier = createVerify(algToHash(alg));
    verifier.update(data);
    return verifier.verify(publicKey, signature);
  } catch {
    return false;
  }
}

function algToHash(alg: string): string {
  if (alg.endsWith('256')) return 'SHA256';
  if (alg.endsWith('384')) return 'SHA384';
  if (alg.endsWith('512')) return 'SHA512';
  throw new IdTokenVerificationError(`Unsupported JWT algorithm: ${alg}`);
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Options for JWT claims validation beyond signature verification.
 *
 * Signature verification alone is not enough — an attacker with a valid token from a different
 * issuer or audience can pass signature checks. Pass expectedIssuer and expectedAudience to
 * prevent token substitution attacks. Without them, id_token claims are unauthenticated
 * (signature verified, but not bound to this client).
 *
 * `exp` is always validated — expired tokens must not authenticate.
 */
export interface VerifyIdTokenOptions {
  /** Expected `iss` claim. Mismatch throws IdTokenVerificationError. */
  expectedIssuer?: string;
  /** Expected `aud` claim. Mismatch throws IdTokenVerificationError. */
  expectedAudience?: string;
}

/**
 * Verify an id_token's signature against the JWKS at jwks_uri, then validate
 * standard time and identity claims.
 *
 * Fetches the JWKS (cached), finds the matching key (by kid or alg/kty),
 * imports the public key, verifies the signature, and then validates:
 *   - exp  (always): token must not be expired
 *   - iss  (if expectedIssuer provided): must match
 *   - aud  (if expectedAudience provided): must be present in aud claim
 *
 * On kid mismatch (key rotation): automatically cache-busts and retries once.
 *
 * @param idToken  The raw id_token JWT string from the token endpoint.
 * @param jwksUri  The JWKS URI from the provider's discovery document.
 * @param options  Optional claims validation (iss, aud). exp is always validated.
 * @returns        The decoded (and now trusted) JWT payload.
 * @throws         IdTokenVerificationError if the signature or any claim is invalid.
 * @throws         AuthUnavailableError if the JWKS endpoint is unreachable.
 */
export async function verifyIdTokenSignature(
  idToken: string,
  jwksUri: string,
  options?: VerifyIdTokenOptions,
): Promise<Record<string, unknown>> {
  const parts = idToken.split('.');
  if (parts.length !== 3) {
    throw new IdTokenVerificationError(
      'id_token is not a valid JWT (expected 3 dot-separated parts)',
    );
  }

  const [headerB64, payloadB64, signatureB64] = parts;

  let header: Record<string, unknown>;
  try {
    header = JSON.parse(Buffer.from(headerB64, 'base64url').toString('utf8'));
  } catch {
    throw new IdTokenVerificationError('id_token header is not valid JSON');
  }

  const alg = header.alg as string | undefined;
  const kid = header.kid as string | undefined;

  if (!alg) {
    throw new IdTokenVerificationError('id_token is missing the alg header field');
  }

  if (!ALLOWED_ALGS.has(alg)) {
    throw new IdTokenVerificationError(`Unsupported or disallowed JWT algorithm: ${alg}`);
  }

  const signingInput = `${headerB64}.${payloadB64}`;
  const signature = Buffer.from(signatureB64, 'base64url');

  let keys = await fetchJwks(jwksUri);
  let jwk = findKey(keys, kid, alg);
  let jwksCacheBusted = false;

  if (!jwk && kid) {
    // kid not found — keys may have rotated. Bust cache once, subject to cooldown.
    const lastBust = jwksCacheBustCooldown.get(jwksUri) ?? 0;
    if (Date.now() - lastBust > JWKS_BUST_COOLDOWN_MS) {
      jwksCacheBustCooldown.set(jwksUri, Date.now());
      keys = await fetchJwks(jwksUri, /* bustCache */ true);
      jwk = findKey(keys, kid, alg);
      jwksCacheBusted = true;
    }
  }

  if (!jwk) {
    throw new IdTokenVerificationError(
      `No JWKS key found for alg=${alg}` + (kid ? `, kid=${kid}` : ''),
    );
  }

  // Import the public key from JWK format (Node.js >=15 supports JWK import)
  let publicKey: ReturnType<typeof createPublicKey>;
  try {
    publicKey = createPublicKey({ key: jwk as JsonWebKey, format: 'jwk' });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : '';
    throw new IdTokenVerificationError(`Failed to import JWKS key: ${message}`);
  }

  // If sig fails and JWKS not yet busted, retry once — handles key material rotation under same kid.
  let verified = verifySignature(alg, signingInput, publicKey, signature);
  if (!verified && kid && !jwksCacheBusted) {
    const lastBust = jwksCacheBustCooldown.get(jwksUri) ?? 0;
    if (Date.now() - lastBust > JWKS_BUST_COOLDOWN_MS) {
      jwksCacheBustCooldown.set(jwksUri, Date.now());
      keys = await fetchJwks(jwksUri, true);
      const freshJwk = findKey(keys, kid, alg);
      if (freshJwk) {
        const freshKey = createPublicKey({ key: freshJwk as JsonWebKey, format: 'jwk' });
        verified = verifySignature(alg, signingInput, freshKey, signature);
      }
    }
  }
  if (!verified) {
    throw new IdTokenVerificationError(
      `id_token signature is invalid (alg=${alg}${kid ? `, kid=${kid}` : ''})`,
    );
  }

  let payload: Record<string, unknown>;
  try {
    payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
  } catch {
    throw new IdTokenVerificationError('id_token payload is not valid JSON');
  }

  // Claims validation: signature valid != token valid for this session.
  // exp/iss/aud bind the token to this client and prevent replay of tokens issued to other parties.

  // exp: mandatory — tokens without an expiry can be replayed indefinitely.
  const now = Math.floor(Date.now() / 1000);
  const exp = payload.exp;
  if (exp === undefined) {
    throw new IdTokenVerificationError('id_token is missing required exp claim');
  }
  if (typeof exp !== 'number') {
    throw new IdTokenVerificationError('id_token exp claim is not a number');
  }
  if (now > exp) {
    throw new IdTokenVerificationError(
      `id_token is expired (exp=${exp}, now=${now}, delta=${now - exp}s)`,
    );
  }

  const nbf = payload.nbf;
  if (nbf !== undefined) {
    if (typeof nbf !== 'number') {
      throw new IdTokenVerificationError('id_token nbf claim is not a number');
    }
    if (now < nbf) {
      throw new IdTokenVerificationError(
        `id_token is not yet valid (nbf=${nbf}, now=${now}, delta=${nbf - now}s)`,
      );
    }
  }

  if (options?.expectedIssuer !== undefined) {
    const iss = payload.iss;
    if (iss !== options.expectedIssuer) {
      throw new IdTokenVerificationError(
        `id_token issuer mismatch: expected "${options.expectedIssuer}", got "${iss ?? '(missing)'}"`,
      );
    }
  }

  // aud: validate when caller provides expectedAudience.
  // aud may be a single string or an array (multi-party tokens).
  if (options?.expectedAudience !== undefined) {
    const aud = payload.aud;
    const audList = Array.isArray(aud) ? aud : aud !== undefined ? [aud] : [];
    if (!audList.includes(options.expectedAudience)) {
      throw new IdTokenVerificationError(
        `id_token audience does not include expected client "${options.expectedAudience}"`,
      );
    }
  }

  return payload;
}

/** Clear the module-level JWKS cache and cooldown state. Exported for testing only. */
export function clearJwksCache(): void {
  jwksCache.clear();
  jwksCacheBustCooldown.clear();
}

// ─── Error Type ───────────────────────────────────────────────────────────────

/**
 * Thrown when id_token signature verification fails for any reason other than
 * an unreachable JWKS endpoint (which throws AuthUnavailableError).
 *
 * Callers should map this to a CredentialInvalidError or AuthUnavailableError
 * with appropriate context.
 */
export class IdTokenVerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'IdTokenVerificationError';
  }
}
