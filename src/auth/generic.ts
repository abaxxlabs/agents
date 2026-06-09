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
 * OidcProvider for standard providers (Google, Azure AD, Okta, Keycloak).
 * fetchUserInfo() is the primary identity path. humanDid is derived deterministically
 * from sha256(issuerUrl + sub) to prevent sub collisions across providers.
 */

import { randomBytes, createHash, createPrivateKey, createPublicKey } from 'node:crypto';
import type {
  OidcProvider,
  OidcTokenResponse,
  OidcIdentity,
  AuthorizationUrlResult,
} from './provider.js';
import { AuthUnavailableError } from '#errors/index.js';
import { PendingFlowStore, PendingFlowError } from './pending-flow-store.js';
import { verifyIdTokenSignature, IdTokenVerificationError } from './jwks-verify.js';
import { base58Encode } from '#crypto/base58.js';
import {
  validateDiscoveredEndpoint,
  parseCacheControlMaxAge,
  DEFAULT_DISCOVERY_TTL_MS,
  MIN_DISCOVERY_TTL_MS,
} from './discovery-utils.js';
import { composeConsumerDomains } from '#identity/index.js';
import {
  isJsonObject,
  parseJwtPayloadClaims,
  parseOidcTokenResponse,
  readOptionalString,
  readOptionalStringArray,
  type JsonObject,
} from './oidc-payload.js';

export interface GenericOidcConfig {
  /** OIDC issuer URL — used for discovery and humanDid seed. e.g. https://accounts.google.com */
  issuerUrl: string;
  clientId: string;
  clientSecret?: string;
  redirectUri?: string;
  /** OAuth scopes to request. Defaults to 'openid profile email'. */
  scopes?: string[];
  /** Discovery cache TTL (ms). Defaults to 1 hour. Coordinate with the provider's key rotation schedule. */
  discoveryCacheTtlMs?: number;
  /**
   * Extra consumer domains for email-domain org fallback. Must match the value
   * passed to OrgBoundary.extract() so the two engines agree byte-for-byte.
   */
  extraConsumerDomains?: readonly string[];
  /**
   * Hostnames allowed for cross-origin discovery endpoints.
   * Blocks SSRF via compromised discovery documents pointing to attacker-controlled hosts.
   */
  allowedCrossOriginHosts?: readonly string[];
}

interface OidcDiscovery {
  issuer?: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint?: string;
  jwks_uri: string;
  code_challenge_methods_supported?: string[];
}

function readRequiredDiscoveryString(
  doc: JsonObject,
  field: string,
  discoveryUrl: string,
): string {
  const value = readOptionalString(doc, field);
  if (!value) {
    throw new AuthUnavailableError(
      `OIDC discovery missing required field: ${field} at ${discoveryUrl}`,
    );
  }
  return value;
}

function parseOidcDiscovery(payload: unknown, discoveryUrl: string): OidcDiscovery {
  if (!isJsonObject(payload)) {
    throw new AuthUnavailableError(
      `OIDC discovery missing required field: authorization_endpoint at ${discoveryUrl}`,
    );
  }

  return {
    issuer: readOptionalString(payload, 'issuer'),
    authorization_endpoint: readRequiredDiscoveryString(payload, 'authorization_endpoint', discoveryUrl),
    token_endpoint: readRequiredDiscoveryString(payload, 'token_endpoint', discoveryUrl),
    userinfo_endpoint: readOptionalString(payload, 'userinfo_endpoint'),
    jwks_uri: readRequiredDiscoveryString(payload, 'jwks_uri', discoveryUrl),
    code_challenge_methods_supported: readOptionalStringArray(payload, 'code_challenge_methods_supported'),
  };
}

export class GenericOidcProvider implements OidcProvider {
  readonly issuerUrl: string;

  private config: GenericOidcConfig;
  /** Cached discovery document. TTL from Cache-Control max-age, capped by config. */
  private discoveryCache: { doc: OidcDiscovery; expiresAt: number } | null = null;
  private discoveryTtlMs: number;
  /** In-process PKCE state store — one instance per provider. */
  private flowStore = new PendingFlowStore();

  constructor(config: GenericOidcConfig) {
    this.config = config;
    this.issuerUrl = config.issuerUrl;
    this.discoveryTtlMs = config.discoveryCacheTtlMs ?? DEFAULT_DISCOVERY_TTL_MS;
  }

  // ─── Discovery ───────────────────────────────────────────────────

  /** Fetch and cache the OIDC discovery document. Validates required fields on load. */
  private async discover(): Promise<OidcDiscovery> {
    const now = Date.now();
    if (this.discoveryCache && now < this.discoveryCache.expiresAt) {
      return this.discoveryCache.doc;
    }

    const discoveryUrl = `${this.config.issuerUrl}/.well-known/openid-configuration`;
    let payload: unknown;
    let cacheControlMaxAge: number | undefined;
    try {
      const res = await fetch(discoveryUrl);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      cacheControlMaxAge = parseCacheControlMaxAge(res.headers.get('cache-control'));
      payload = await res.json();
    } catch {
      throw new AuthUnavailableError(this.config.issuerUrl);
    }

    const doc = parseOidcDiscovery(payload, discoveryUrl);

    // Clamp TTL between MIN (prevent fetch-loop abuse) and configured ceiling.
    const effectiveTtl =
      cacheControlMaxAge !== undefined
        ? Math.max(MIN_DISCOVERY_TTL_MS, Math.min(cacheControlMaxAge * 1000, this.discoveryTtlMs))
        : this.discoveryTtlMs;

    const issuerOrigin = new URL(this.config.issuerUrl).origin;
    const crossOriginHosts = this.config.allowedCrossOriginHosts;
    validateDiscoveredEndpoint(
      doc.authorization_endpoint,
      'authorization_endpoint',
      issuerOrigin,
      'Generic OIDC',
      crossOriginHosts,
    );
    validateDiscoveredEndpoint(
      doc.token_endpoint,
      'token_endpoint',
      issuerOrigin,
      'Generic OIDC',
      crossOriginHosts,
    );
    if (doc.userinfo_endpoint) {
      validateDiscoveredEndpoint(
        doc.userinfo_endpoint,
        'userinfo_endpoint',
        issuerOrigin,
        'Generic OIDC',
        crossOriginHosts,
      );
    }

    this.discoveryCache = { doc, expiresAt: now + effectiveTtl };
    return this.discoveryCache.doc;
  }

  // ─── OidcProvider: Authorization URL ────────────────────────────

  /** Build a PKCE S256 authorization URL. Library generates and owns state + code verifier. */
  async buildAuthorizationUrl(): Promise<AuthorizationUrlResult> {
    const discovery = await this.discover();

    const codeVerifier = randomBytes(32).toString('base64url');
    const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');
    const state = randomBytes(16).toString('hex');
    const scopes = this.config.scopes ?? ['openid', 'profile', 'email'];

    const authUrl = new URL(discovery.authorization_endpoint);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('client_id', this.config.clientId);
    authUrl.searchParams.set(
      'redirect_uri',
      this.config.redirectUri ?? 'http://localhost:3000/callback',
    );
    authUrl.searchParams.set('scope', scopes.join(' '));
    authUrl.searchParams.set('code_challenge', codeChallenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');
    authUrl.searchParams.set('state', state);

    this.flowStore.register(state, codeVerifier);

    return { url: authUrl.toString(), state, codeVerifier };
  }

  // ─── OidcProvider: Code Exchange ─────────────────────────────────

  /** Exchange code for tokens, then fetchUserInfo(). CSRF/PKCE validated before any HTTP call. */
  async exchangeCode(code: string, state: string, codeVerifier: string): Promise<OidcIdentity> {
    // CSRF + PKCE validation before any network call.
    try {
      this.flowStore.consume(state, codeVerifier);
    } catch (err) {
      if (err instanceof PendingFlowError) {
        throw new AuthUnavailableError(`OAuth state validation failed: ${err.message}`);
      }
      throw err;
    }

    const discovery = await this.discover();

    const tokenParams: Record<string, string> = {
      grant_type: 'authorization_code',
      code,
      redirect_uri: this.config.redirectUri ?? 'http://localhost:3000/callback',
      client_id: this.config.clientId,
      code_verifier: codeVerifier,
    };
    if (this.config.clientSecret) {
      tokenParams.client_secret = this.config.clientSecret;
    }

    const tokenRes = await fetch(discovery.token_endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(tokenParams),
    });

    if (!tokenRes.ok) {
      const body = await tokenRes.text().catch(() => '');
      throw new AuthUnavailableError(`Token exchange failed (HTTP ${tokenRes.status}): ${body}`);
    }

    const tokens = parseOidcTokenResponse(await tokenRes.json());

    // Verify id_token if present. Missing id_token is acceptable — fetchUserInfo() is primary.
    if (tokens.id_token) {
      try {
        await verifyIdTokenSignature(tokens.id_token, discovery.jwks_uri, {
          expectedIssuer: this.config.issuerUrl,
          expectedAudience: this.config.clientId,
        });
      } catch (err) {
        if (err instanceof IdTokenVerificationError) {
          throw new AuthUnavailableError(`id_token signature verification failed: ${err.message}`);
        }
        throw err;
      }
    }

    if (!tokens.access_token) {
      throw new AuthUnavailableError(
        'Token exchange returned neither id_token nor access_token. Cannot verify identity.',
      );
    }

    return this.fetchUserInfo(tokens.access_token);
  }

  // ─── OidcProvider: Identity Extraction ───────────────────────────

  /** Extract identity from token claims only. Returns Partial. No I/O. */
  parseIdentityFromToken(tokenResponse: OidcTokenResponse): Partial<OidcIdentity> {
    let idTokenClaims: Record<string, unknown> = {};
    if (tokenResponse.id_token) {
      idTokenClaims = parseJwtPayloadClaims(tokenResponse.id_token);
    }

    const rawDid =
      (idTokenClaims.did as string | undefined) ??
      (typeof idTokenClaims.sub === 'string' && idTokenClaims.sub.startsWith('did:')
        ? idTokenClaims.sub
        : undefined);

    return {
      humanDid: rawDid,
      email: idTokenClaims.email as string | undefined,
      org: (idTokenClaims.hd ?? idTokenClaims.tid) as string | undefined,
      name: idTokenClaims.name as string | undefined,
      claims: idTokenClaims,
    };
  }

  /** Fetch full identity from userinfo and derive a stable humanDid from issuerUrl+sub. */
  async fetchUserInfo(accessToken: string): Promise<OidcIdentity> {
    const discovery = await this.discover();

    if (!discovery.userinfo_endpoint) {
      throw new AuthUnavailableError(
        `Provider ${this.config.issuerUrl} has no userinfo_endpoint in discovery document`,
      );
    }

    const res = await fetch(discovery.userinfo_endpoint, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (!res.ok) {
      const body = await res.text().catch(() => '');
      throw new AuthUnavailableError(`Userinfo failed (HTTP ${res.status}): ${body}`);
    }

    const userInfo = (await res.json()) as Record<string, unknown>;
    const sub = userInfo.sub as string;
    if (!sub) {
      throw new AuthUnavailableError('Userinfo response missing sub claim');
    }

    const humanDid = sub.startsWith('did:') ? sub : this.deriveHumanDid(sub);
    const email = userInfo.email as string | undefined;

    // Extract org from hosted domain (Google), tenant ID (Azure), or email domain
    const org = this.extractOrg(userInfo, email);

    return {
      humanDid,
      issuer: this.config.issuerUrl,
      sub,
      email,
      org,
      name: userInfo.name as string | undefined,
      claims: userInfo,
    };
  }

  // ─── Helpers ─────────────────────────────────────────────────────

  /**
   * Derive a deterministic did:key from issuerUrl + sub.
   * WARNING: private key is derivable by anyone who knows issuerUrl+sub -- no key confidentiality.
   */
  deriveHumanDid(sub: string): string {
    // Null-byte separator prevents preimage collision across providers with identical sub values.
    const seed = createHash('sha256')
      .update(this.config.issuerUrl + '\x00' + sub)
      .digest();

    // Ed25519 PKCS8 DER: 16-byte ASN.1 header + 32-byte seed.
    const pkcs8Header = Buffer.from('302e020100300506032b657004220420', 'hex');
    const pkcs8Der = Buffer.concat([pkcs8Header, seed]);

    const privateKey = createPrivateKey({ key: pkcs8Der, format: 'der', type: 'pkcs8' });
    const publicKeyObj = createPublicKey(privateKey);
    const pubKeyDer = publicKeyObj.export({ type: 'spki', format: 'der' }) as Buffer;

    const rawPublicKey = pubKeyDer.subarray(-32); // last 32 bytes of Ed25519 SPKI DER

    const multicodec = Buffer.concat([Buffer.from([0xed, 0x01]), rawPublicKey]); // Ed25519 prefix
    const humanDid = `did:key:z${base58Encode(multicodec)}`;

    return humanDid;
  }

  /** Extract org: hd (Google) > tid (Azure) > email domain. Consumer domains return undefined. */
  private extractOrg(
    userInfo: Record<string, unknown>,
    email: string | undefined,
  ): string | undefined {
    if (userInfo.hd && typeof userInfo.hd === 'string') return userInfo.hd;   // Google Workspace
    if (userInfo.tid && typeof userInfo.tid === 'string') return userInfo.tid; // Azure AD

    if (email) {
      const domain = email.split('@')[1]?.toLowerCase();
      if (domain) {
        const consumerDomains = composeConsumerDomains(this.config.extraConsumerDomains);
        if (!consumerDomains.has(domain)) {
          return domain;
        }
      }
    }

    return undefined;
  }
}
