import { randomUUID } from 'node:crypto';
import type { ServerIdentity } from './server-identity.js';
import type { OidcIdentity } from '#auth/provider.js';
import { OrgBoundary } from './org-boundary.js';

const DEFAULT_MEMBERSHIP_TTL_SECONDS = 24 * 60 * 60;
const REFRESH_THRESHOLD_RATIO = 0.8;
/** Application-layer grace period after `exp`. Protects in-flight operations. VcVerifier enforces hard expiry. */
const OVERLAP_WINDOW_SECONDS = 5 * 60;

export interface IdentityBindingCredential {
  jwt: string;
  userDid: string;
  orgDomain: string | null;
  oauthIssuer: string;
  oauthSubject: string;
  serverDid: string;
  exp: number;
  iat: number;
  jti: string;
}

export interface BindingOptions {
  membershipTtlSeconds?: number;
  extraConsumerDomains?: readonly string[];
}

/** Binds a verified OIDC identity (userDid + claims) to the server's DID. */
export async function createBindingCredential(
  serverIdentity: ServerIdentity,
  userDid: string,
  oauthClaims: OidcIdentity,
  options: BindingOptions = {},
): Promise<IdentityBindingCredential> {
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

/** Refresh a binding with updated OIDC claims. Old binding stays valid until exp + overlap window. */
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

/** Returns true when the binding has used >=80% of its TTL. */
export function shouldRefresh(
  binding: IdentityBindingCredential,
  nowSeconds = Math.floor(Date.now() / 1000),
): boolean {
  const ttl = binding.exp - binding.iat;
  const elapsed = nowSeconds - binding.iat;
  return elapsed >= ttl * REFRESH_THRESHOLD_RATIO;
}

/** Returns true when current time > exp + OVERLAP_WINDOW_SECONDS. */
export function isExpired(
  binding: IdentityBindingCredential,
  nowSeconds = Math.floor(Date.now() / 1000),
): boolean {
  return nowSeconds > binding.exp + OVERLAP_WINDOW_SECONDS;
}

/** Returns null if the JWT is malformed or not an IdentityBindingCredential. Does NOT verify the signature. */
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
