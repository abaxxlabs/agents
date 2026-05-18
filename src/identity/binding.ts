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
 * Identity Binding — connects OIDC identity to the server's DID.
 *
 * Issued by the server's DID so verifiers can verify the chain:
 *   OIDC provider → user identity → server binding → agent DID
 *
 * Lifetime: 24h default. Refresh threshold: 80%. Overlap window: 5 minutes past expiry
 * so in-flight operations complete. Refresh failure returns the existing binding (still
 * valid during the overlap window) — does NOT throw.
 */

import { randomUUID } from 'node:crypto';
import type { ServerIdentity } from './server-identity.js';
import type { OidcIdentity } from '../auth/provider.js';
import { OrgBoundary } from './org-boundary.js';

// ─── Constants ────────────────────────────────────────────────────────────────

/** Default binding lifetime: 24 hours. Configurable per createBindingCredential call. */
const DEFAULT_MEMBERSHIP_TTL_SECONDS = 24 * 60 * 60;

/** Refresh at 80% of TTL — leaves headroom for brief OIDC outages before auth failures. */
const REFRESH_THRESHOLD_RATIO = 0.8;

/** Application-layer grace period after `exp` — protects in-flight operations. VcVerifier enforces hard expiry. */
const OVERLAP_WINDOW_SECONDS = 5 * 60;

// ─── Public Types ─────────────────────────────────────────────────────────────

/**
 * An identity binding credential: the evidence that a real OIDC-verified user
 * authorized this agents instance to represent them.
 *
 * The jwt field is a signed JWT-VC. All other fields are pre-parsed from the JWT
 * for convenient access without decode overhead on the hot path.
 */
export interface IdentityBindingCredential {
  /** Signed JWT-encoded VC. Issuer is the server's DID (ServerIdentity.did). */
  jwt: string;
  /** The authenticated user's DID. */
  userDid: string;
  /** Org domain extracted from OIDC claims (e.g., 'company.com', 'azure-tenant-guid'). */
  orgDomain: string | null;
  /** OIDC issuer URL — which provider authenticated the user. */
  oauthIssuer: string;
  /** OIDC sub claim — stable per-user-per-provider identifier. */
  oauthSubject: string;
  /** The server DID that issued this binding (for chain verification). */
  serverDid: string;
  /** Expiry time (Unix seconds). */
  exp: number;
  /** Issue time (Unix seconds). */
  iat: number;
  /** Unique ID for this credential (jti). Used for revocation and audit. */
  jti: string;
}

/**
 * Options for createBindingCredential.
 *
 * membershipTtlSeconds: how long the binding is valid. Defaults to 24h.
 *   Should match or be less than the OAuth token lifetime for the OIDC provider.
 *   Long-lived bindings reduce OIDC roundtrips; short-lived bindings limit blast
 *   radius if a binding is compromised. 24h is a good default for enterprise use.
 *
 * extraConsumerDomains: optional extension of the consumer-domain registry
 *   used by `OrgBoundary.extract()` when computing the binding's `orgDomain`.
 *   Should be the SAME list the consumer threads to
 *   `GenericOidcProvider({ extraConsumerDomains })` and `AgentScope`'s
 *   `config.orgBoundary.extraConsumerDomains` so all three engines agree on
 *   which email-domain fallbacks count as enterprise. When omitted, only the
 *   built-in consumer-domain registry is excluded.
 */
export interface BindingOptions {
  membershipTtlSeconds?: number;
  extraConsumerDomains?: readonly string[];
}

// ─── Binding Creation ─────────────────────────────────────────────────────────

/**
 * Create a new identity binding credential.
 *
 * Binds a verified OIDC identity (userDid + claims) to the server's DID.
 * The resulting VC can be stored in the keystore and presented to verifiers
 * that trust the server's DID.
 *
 * @param serverIdentity  The server's DID + signer.
 * @param userDid         The authenticated user's DID (from OIDC flow).
 * @param oauthClaims     The full OidcIdentity produced by the OIDC provider.
 * @param options         Optional: membershipTtlSeconds override.
 */
export async function createBindingCredential(
  serverIdentity: ServerIdentity,
  userDid: string,
  oauthClaims: OidcIdentity,
  options: BindingOptions = {},
): Promise<IdentityBindingCredential> {
  // Runtime guard: TypeScript only enforces OidcIdentity.issuer/.sub at compile time.
  if (!oauthClaims.issuer || typeof oauthClaims.issuer !== 'string') {
    throw new Error(
      'Cannot issue IdentityBindingCredential: OidcIdentity.issuer is missing or not a string. ' +
        'The OIDC provider must populate the issuer field (the iss claim from discovery metadata).',
    );
  }
  if (!oauthClaims.sub || typeof oauthClaims.sub !== 'string') {
    throw new Error(
      'Cannot issue IdentityBindingCredential: OidcIdentity.sub is missing or not a string. ' +
        'The OIDC provider must populate the sub field (the stable per-user subject identifier).',
    );
  }

  const ttl = options.membershipTtlSeconds ?? DEFAULT_MEMBERSHIP_TTL_SECONDS;
  const now = Math.floor(Date.now() / 1000);
  const exp = now + ttl;
  const jti = randomUUID();

  const orgResult = OrgBoundary.extract(oauthClaims, options.extraConsumerDomains);

  const subject = {
    id: userDid,
    oauthIssuer: oauthClaims.issuer,
    oauthSubject: oauthClaims.sub,
    orgDomain: orgResult.org,
    serverDid: serverIdentity.did,
  };

  const payload = {
    iss: serverIdentity.did,
    sub: userDid,
    jti,
    iat: now,
    exp,
    vc: {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: ['VerifiableCredential', 'IdentityBindingCredential'],
      credentialSubject: subject,
    },
  };

  const jwt = await serverIdentity.signer.signJwt(payload);

  return {
    jwt,
    userDid,
    orgDomain: orgResult.org,
    oauthIssuer: oauthClaims.issuer,
    oauthSubject: oauthClaims.sub,
    serverDid: serverIdentity.did,
    exp,
    iat: now,
    jti,
  };
}

// ─── Binding Refresh ──────────────────────────────────────────────────────────

/**
 * Refresh a binding credential with updated OIDC claims.
 *
 * Issues a new binding with a fresh TTL. The old binding remains valid until
 * its exp (+ OVERLAP_WINDOW_SECONDS) so in-flight operations are not interrupted.
 *
 * Call this when shouldRefresh(existing) returns true. The new binding should
 * be stored in the keystore in place of the old one.
 *
 * @param serverIdentity  The server's current DID + signer.
 * @param existing        The binding to refresh (used for options inheritance).
 * @param newOauthClaims  Fresh OIDC claims from a re-authentication.
 * @param options         Optional: TTL override for the refreshed binding.
 */
export async function refreshBindingCredential(
  serverIdentity: ServerIdentity,
  existing: IdentityBindingCredential,
  newOauthClaims: OidcIdentity,
  options: BindingOptions = {},
): Promise<IdentityBindingCredential> {
  const originalTtl = existing.exp - existing.iat;
  const ttl = options.membershipTtlSeconds ?? originalTtl;

  return createBindingCredential(serverIdentity, existing.userDid, newOauthClaims, {
    membershipTtlSeconds: ttl,
    ...(options.extraConsumerDomains !== undefined && {
      extraConsumerDomains: options.extraConsumerDomains,
    }),
  });
}

// ─── Binding Status Checks ────────────────────────────────────────────────────

/**
 * Check whether a binding credential should be proactively refreshed.
 *
 * Returns true when the binding has used ≥80% of its TTL (REFRESH_THRESHOLD_RATIO).
 * The caller should call refreshBindingCredential() when this returns true.
 *
 * Does NOT check whether the binding is hard-expired. Use isExpired() for that.
 * A binding can be shouldRefresh()=true but isExpired()=false — that is the
 * normal refresh window and is the intended operating state.
 *
 * @param binding   The binding to check.
 * @param nowSeconds  Current time in seconds (defaults to Date.now()/1000).
 */
export function shouldRefresh(
  binding: IdentityBindingCredential,
  nowSeconds = Math.floor(Date.now() / 1000),
): boolean {
  const ttl = binding.exp - binding.iat;
  const elapsed = nowSeconds - binding.iat;
  return elapsed >= ttl * REFRESH_THRESHOLD_RATIO;
}

/**
 * Check whether a binding credential has expired (including the overlap window).
 *
 * Returns false during the OVERLAP_WINDOW_SECONDS grace period after exp.
 * Returns true when: current time > exp + OVERLAP_WINDOW_SECONDS.
 *
 * This is an application-layer check — VcVerifier.verify() enforces hard expiry
 * based on the JWT `exp` claim. This function exists for callers that want to
 * keep using a binding slightly past its exp while a refresh is in progress.
 *
 * @param binding     The binding to check.
 * @param nowSeconds  Current time in seconds (defaults to Date.now()/1000).
 */
export function isExpired(
  binding: IdentityBindingCredential,
  nowSeconds = Math.floor(Date.now() / 1000),
): boolean {
  return nowSeconds > binding.exp + OVERLAP_WINDOW_SECONDS;
}

/**
 * Parse an IdentityBindingCredential from its JWT string.
 *
 * Does NOT verify the signature — call VcVerifier.verify() for that.
 * This is a pure decode step for access to the credential fields without
 * waiting for async key resolution.
 *
 * Returns null if the JWT is malformed or not an IdentityBindingCredential.
 */
export function parseBindingCredential(jwt: string): IdentityBindingCredential | null {
  try {
    const parts = jwt.split('.');
    if (parts.length !== 3) return null;

    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    const vc = payload.vc;

    if (!vc || !Array.isArray(vc.type) || !vc.type.includes('IdentityBindingCredential')) {
      return null;
    }

    const subject = vc.credentialSubject;
    if (!subject || !subject.id) return null;

    return {
      jwt,
      userDid: subject.id,
      orgDomain: subject.orgDomain ?? null,
      oauthIssuer: subject.oauthIssuer,
      oauthSubject: subject.oauthSubject,
      serverDid: subject.serverDid,
      exp: payload.exp,
      iat: payload.iat,
      jti: payload.jti,
    };
  } catch {
    return null;
  }
}
