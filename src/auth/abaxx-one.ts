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
 * OidcProvider implementation for AbaxxOne.
 *
 * AbaxxOne embeds agent DIDs in token responses so parseIdentityFromToken()
 * can return a complete identity without fetchUserInfo(). Uses the proprietary
 * X-Session-ID header and /.well-known/openid_configuration discovery path.
 */

import { randomBytes, createHash } from 'node:crypto';
import type {
  OidcProvider,
  OidcTokenResponse,
  OidcIdentity,
  AuthorizationUrlResult,
} from './provider.js';
import { AuthUnavailableError, ParentCredentialRequestFailedError } from '../errors.js';
import { PendingFlowStore, PendingFlowError } from './pending-flow-store.js';
import { verifyIdTokenSignature, IdTokenVerificationError } from './jwks-verify.js';
import {
  validateDiscoveredEndpoint,
  parseCacheControlMaxAge,
  DEFAULT_DISCOVERY_TTL_MS,
  MIN_DISCOVERY_TTL_MS,
} from './discovery-utils.js';
import {
  isJsonObject,
  parseJwtPayloadClaims,
  parseOidcTokenResponse,
  readOptionalString,
  readOptionalStringArray,
  type JsonObject,
} from './oidc-payload.js';

// Only did:key and did:dht are valid DID methods in this stack.
// Accept no others from tokens or userinfo responses.
const VALID_DID_PREFIXES = ['did:key:', 'did:dht:'] as const;
function isValidDid(did: string): boolean {
  return VALID_DID_PREFIXES.some((prefix) => did.startsWith(prefix));
}

export interface AbaxxOneConfig {
  /** Base URL of the AbaxxOne tenant, e.g. https://id.abaxx.com */
  tenantUrl: string;
  clientId: string;
  clientSecret?: string;
  redirectUri?: string;
  /** For programmatic/CLI login only — not used in browser redirect mode. */
  email?: string;
  password?: string;
  /** Discovery document cache TTL in milliseconds. Defaults to 1 hour.
   * AbaxxOne key rotation is tenant-controlled — coordinate this value
   * with the tenant's rotation schedule to minimize stale JWKS windows. */
  discoveryCacheTtlMs?: number;
  /**
   * Hostnames allowed to appear as cross-origin discovery endpoints.
   *
   * OIDC discovery documents can name token, authorization, and userinfo
   * endpoints on a different origin than the issuer. A compromised discovery
   * document could redirect token exchange to an attacker-controlled HTTPS
   * host. This per-issuer allowlist blocks unlisted cross-origin hosts before
   * any credentials are sent.
   *
   * Endpoints whose host matches the issuer origin do not need to be listed.
   * If a cross-origin endpoint is discovered and this field is undefined,
   * discovery resolution throws `DiscoveryEndpointBlockedError`.
   *
   * @example
   * // AbaxxOne tenant with a separate auth service host:
   * { allowedCrossOriginHosts: ['auth.abaxx.com'] }
   */
  allowedCrossOriginHosts?: readonly string[];
}

/** AbaxxOne OIDC discovery shape (uses underscores, not hyphens). */
interface AbaxxOneDiscovery {
  issuer?: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
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
      `AbaxxOne discovery missing required field: ${field} at ${discoveryUrl}`,
    );
  }
  return value;
}

function parseAbaxxOneDiscovery(payload: unknown, discoveryUrl: string): AbaxxOneDiscovery {
  if (!isJsonObject(payload)) {
    throw new AuthUnavailableError(
      `AbaxxOne discovery missing required field: authorization_endpoint at ${discoveryUrl}`,
    );
  }

  return {
    issuer: readOptionalString(payload, 'issuer'),
    authorization_endpoint: readRequiredDiscoveryString(payload, 'authorization_endpoint', discoveryUrl),
    token_endpoint: readRequiredDiscoveryString(payload, 'token_endpoint', discoveryUrl),
    userinfo_endpoint: readRequiredDiscoveryString(payload, 'userinfo_endpoint', discoveryUrl),
    jwks_uri: readRequiredDiscoveryString(payload, 'jwks_uri', discoveryUrl),
    code_challenge_methods_supported: readOptionalStringArray(payload, 'code_challenge_methods_supported'),
  };
}

// ─── SSRF Guard ──────────────────────────────────────────────────────────────

export class AbaxxOneOidcProvider implements OidcProvider {
  readonly issuerUrl: string;

  private config: AbaxxOneConfig;
  /** Cached discovery document. TTL from Cache-Control max-age, capped by config. */
  private discoveryCache: { doc: AbaxxOneDiscovery; expiresAt: number } | null = null;
  private discoveryTtlMs: number;
  /** In-process PKCE state store — one instance per provider. */
  private flowStore = new PendingFlowStore();

  constructor(config: AbaxxOneConfig) {
    this.config = config;
    this.issuerUrl = config.tenantUrl;
    this.discoveryTtlMs = config.discoveryCacheTtlMs ?? DEFAULT_DISCOVERY_TTL_MS;
  }

  // ─── Discovery ───────────────────────────────────────────────────

  /** Fetch and cache the AbaxxOne OIDC discovery document. Validates required fields on load. */
  private async discover(): Promise<AbaxxOneDiscovery> {
    const now = Date.now();
    if (this.discoveryCache && now < this.discoveryCache.expiresAt) {
      return this.discoveryCache.doc;
    }

    const discoveryUrl = `${this.config.tenantUrl}/.well-known/openid_configuration`;
    let payload: unknown;
    let cacheControlMaxAge: number | undefined;
    try {
      const res = await fetch(discoveryUrl);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      cacheControlMaxAge = parseCacheControlMaxAge(res.headers.get('cache-control'));
      payload = await res.json();
    } catch {
      throw new AuthUnavailableError(this.config.tenantUrl);
    }

    const doc = parseAbaxxOneDiscovery(payload, discoveryUrl);

    // Clamp TTL between MIN (prevent fetch-loop abuse) and configured ceiling.
    const effectiveTtl =
      cacheControlMaxAge !== undefined
        ? Math.max(MIN_DISCOVERY_TTL_MS, Math.min(cacheControlMaxAge * 1000, this.discoveryTtlMs))
        : this.discoveryTtlMs;

    const issuerOrigin = new URL(this.config.tenantUrl).origin;
    const crossOriginHosts = this.config.allowedCrossOriginHosts;
    validateDiscoveredEndpoint(
      doc.authorization_endpoint,
      'authorization_endpoint',
      issuerOrigin,
      'AbaxxOne',
      crossOriginHosts,
    );
    validateDiscoveredEndpoint(
      doc.token_endpoint,
      'token_endpoint',
      issuerOrigin,
      'AbaxxOne',
      crossOriginHosts,
    );
    validateDiscoveredEndpoint(
      doc.userinfo_endpoint,
      'userinfo_endpoint',
      issuerOrigin,
      'AbaxxOne',
      crossOriginHosts,
    );

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

    const authUrl = new URL(discovery.authorization_endpoint);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('client_id', this.config.clientId);
    authUrl.searchParams.set(
      'redirect_uri',
      this.config.redirectUri ?? 'http://localhost:3000/callback',
    );
    authUrl.searchParams.set('scope', 'openid profile');
    authUrl.searchParams.set('code_challenge', codeChallenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');
    authUrl.searchParams.set('state', state);

    this.flowStore.register(state, codeVerifier);

    return { url: authUrl.toString(), state, codeVerifier };
  }

  // ─── OidcProvider: Code Exchange ─────────────────────────────────

  /** Exchange code for tokens + identity. `_exchangeCodeWithToken()` also returns the access token. */
  async exchangeCode(code: string, state: string, codeVerifier: string): Promise<OidcIdentity> {
    const { identity } = await this._exchangeCodeWithToken(code, state, codeVerifier);
    return identity;
  }

  /**
   * Exchange code and return both identity and access token.
   *
   * Security ordering:
   *   1. flowStore.consume(state, codeVerifier) — validates CSRF state and PKCE verifier
   *      before any HTTP call. Throws PendingFlowError → AuthUnavailableError.
   *   2. verifyIdTokenSignature(id_token, jwks_uri) — verifies the id_token's cryptographic
   *      signature against the provider's JWKS. Without this, id_token claims (including the
   *      DID) are unauthenticated — an unverified id_token is just base64-encoded JSON.
   */
  private async _exchangeCodeWithToken(
    code: string,
    state: string,
    codeVerifier: string,
  ): Promise<{ identity: OidcIdentity; accessToken: string }> {
    // CSRF + PKCE state validation FIRST — before any network call.
    // Reject unknown, expired, or replayed state values immediately.
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

    // id_token signature verification. An unverified id_token is just base64-encoded JSON —
    // anyone can forge it. AbaxxOne relies on id_token claims for DID extraction.
    // If no id_token is returned, we MUST NOT proceed — that would trust unverified claims.
    // Fail closed.
    if (!tokens.id_token) {
      throw new AuthUnavailableError(
        'AbaxxOne token exchange did not return an id_token. ' +
          'Cannot verify identity without a signed id_token.',
      );
    }

    try {
      // Pass expectedIssuer and expectedAudience to prevent token substitution attacks
      // (a valid token from a different provider passes signature verification but not iss/aud).
      await verifyIdTokenSignature(tokens.id_token, discovery.jwks_uri, {
        expectedIssuer: discovery.issuer,
        expectedAudience: this.config.clientId,
      });
    } catch (err) {
      if (err instanceof IdTokenVerificationError) {
        throw new AuthUnavailableError(
          `AbaxxOne id_token signature verification failed: ${err.message}`,
        );
      }
      throw err; // AuthUnavailableError from JWKS fetch propagates as-is
    }

    const partial = this.parseIdentityFromToken(tokens);
    if (partial.humanDid) {
      return { identity: partial as OidcIdentity, accessToken: tokens.access_token };
    }

    const identity = await this.fetchUserInfo(tokens.access_token);
    return { identity, accessToken: tokens.access_token };
  }

  // ─── OidcProvider: Identity Extraction ───────────────────────────

  /**
   * Extract identity from AbaxxOne token claims. Returns a complete OidcIdentity
   * when DID is present; returns Partial (no humanDid) for older tenants that
   * don't embed DID — exchangeCode() falls back to fetchUserInfo() in that case.
   * NO network I/O.
   */
  parseIdentityFromToken(tokenResponse: OidcTokenResponse): Partial<OidcIdentity> {
    // Decode id_token claims without verification (signature already checked upstream)
    let idTokenClaims: Record<string, unknown> = {};
    if (tokenResponse.id_token) {
      idTokenClaims = parseJwtPayloadClaims(tokenResponse.id_token);
    }

    // Only accept did:key and did:dht — reject all other DID methods.
    const rawDid =
      (idTokenClaims.did as string | undefined) ??
      (typeof idTokenClaims.sub === 'string' && idTokenClaims.sub.startsWith('did:')
        ? idTokenClaims.sub
        : undefined);
    const did = rawDid && isValidDid(rawDid) ? rawDid : undefined;

    if (!did) {
      return { claims: idTokenClaims }; // older tenant — fall back to fetchUserInfo()
    }

    return {
      humanDid: did,
      issuer: (idTokenClaims.iss as string | undefined) ?? this.config.tenantUrl,
      sub: (idTokenClaims.sub as string | undefined) ?? did,
      email: idTokenClaims.email as string | undefined,
      org: (idTokenClaims.hd ?? idTokenClaims.tid ?? idTokenClaims.org) as string | undefined,
      name: idTokenClaims.name as string | undefined,
      claims: idTokenClaims,
    };
  }

  /** Fetch full identity from AbaxxOne userinfo. AbaxxOne's response includes a 'did' field. */
  async fetchUserInfo(accessToken: string): Promise<OidcIdentity> {
    const discovery = await this.discover();

    const res = await fetch(discovery.userinfo_endpoint, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (!res.ok) {
      const body = await res.text().catch(() => '');
      throw new AuthUnavailableError(`Userinfo failed (HTTP ${res.status}): ${body}`);
    }

    const userInfo = (await res.json()) as Record<string, unknown>;

    const rawHumanDid = (userInfo.did ?? userInfo.sub) as string | undefined;
    if (!rawHumanDid) {
      throw new AuthUnavailableError('AbaxxOne userinfo returned no DID or sub');
    }
    if (!isValidDid(rawHumanDid)) {
      throw new AuthUnavailableError(
        `AbaxxOne userinfo returned unsupported DID method: ${rawHumanDid.split(':').slice(0, 2).join(':')} — only did:key and did:dht are accepted`,
      );
    }
    const humanDid = rawHumanDid;

    return {
      humanDid,
      issuer: this.config.tenantUrl,
      sub: (userInfo.sub as string | undefined) ?? humanDid,
      email: userInfo.email as string | undefined,
      org: (userInfo.hd ?? userInfo.tid ?? userInfo.org) as string | undefined,
      name: userInfo.name as string | undefined,
      claims: userInfo,
    };
  }

  // ─── Parent-Issued Agent Credentials ────────────────────────────

  /**
   * Request a scoped agent credential signed by the org's DID (not the human's).
   * The returned JWT is verified by the caller before use — this only handles transport.
   *
   * @param accessToken Human's OAuth access token
   * @param agentDid    Agent DID to bind the credential to
   * @param options     Requested scope and TTL
   * @throws {ParentCredentialRequestFailedError} on network failure or non-2xx
   */
  async requestAgentCredential(
    accessToken: string,
    agentDid: string,
    options: { columns: string[]; actions: string[]; expiresIn: string | number },
  ): Promise<{ jwt: string; issuerDid: string }> {
    const url = `${this.config.tenantUrl}/api/v1/credentials/agent`;

    let res: Response;
    try {
      res = await fetch(url, {
        method: 'POST',
        signal: AbortSignal.timeout(5000), // prevent indefinite hang if tenant is slow
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${accessToken}`,
        },
        body: JSON.stringify({
          agentDid,
          scope: {
            columns: options.columns,
            actions: options.actions,
          },
          expiresIn: options.expiresIn,
        }),
      });
    } catch (err) {
      throw new ParentCredentialRequestFailedError(
        this.config.tenantUrl,
        undefined,
        `Network error: ${err instanceof Error ? err.message : 'unknown'}. ` +
          'Verify the tenant URL is reachable and try again.',
      );
    }

    if (!res.ok) {
      const body = await res.text().catch(() => '');
      // Truncate to prevent large server internals from appearing in error messages.
      const truncatedBody =
        typeof body === 'string' && body.length > 200 ? body.slice(0, 200) + '...' : body;
      throw new ParentCredentialRequestFailedError(
        this.config.tenantUrl,
        res.status,
        res.status === 401
          ? 'Access token expired or invalid. Re-authenticate with the parent instance.'
          : res.status === 403
            ? 'Human is not authorized to create agents in this tenant. Contact your AbaxxOne administrator.'
            : `Unexpected error: ${truncatedBody}`,
      );
    }

    const data = (await res.json()) as { jwt: string };
    if (!data.jwt || typeof data.jwt !== 'string') {
      throw new ParentCredentialRequestFailedError(
        this.config.tenantUrl,
        res.status,
        'Tenant returned a response but it did not include a valid JWT. ' +
          'This may indicate a tenant API version mismatch.',
      );
    }

    // Decode iss without verification — caller verifies the full JWT before trusting it.
    let issuerDid: string;
    try {
      const parts = data.jwt.split('.');
      const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
      issuerDid = payload.iss;
      if (!issuerDid || !isValidDid(issuerDid)) {
        throw new Error(`Invalid issuer DID: ${issuerDid}`);
      }
    } catch (err) {
      throw new ParentCredentialRequestFailedError(
        this.config.tenantUrl,
        undefined,
        'Tenant returned a JWT but the issuer DID could not be extracted or is invalid. ' +
          `${err instanceof Error ? err.message : 'Unknown parse error'}`,
      );
    }

    return { jwt: data.jwt, issuerDid };
  }

  // ─── Programmatic Login (CLI mode) ───────────────────────────────

  /**
   * Programmatic login (CLI/tests). Uses AbaxxOne's proprietary
   * POST /auth/login → X-Session-ID → PKCE flow (not in OidcProvider interface).
   * Returns identity + access token so callers can call requestAgentCredential().
   */
  async loginProgrammatic(): Promise<{ identity: OidcIdentity; accessToken: string }> {
    if (!this.config.email || !this.config.password) {
      throw new Error('loginProgrammatic() requires email and password in config');
    }

    const discovery = await this.discover();
    const loginUrl = `${this.config.tenantUrl}/auth/login`;

    const loginRes = await fetch(loginUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: this.config.email, password: this.config.password }),
      signal: AbortSignal.timeout(5000),
    });

    if (!loginRes.ok) {
      const body = await loginRes.text().catch(() => '');
      throw new AuthUnavailableError(`Login failed (HTTP ${loginRes.status}): ${body}`);
    }

    const loginData = (await loginRes.json()) as Record<string, unknown>;
    const sessionId = loginData.session_id as string;
    if (!sessionId) {
      throw new AuthUnavailableError('Login succeeded but no session_id returned');
    }

    const codeVerifier = randomBytes(32).toString('base64url');
    const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');
    const redirectUri = this.config.redirectUri ?? 'http://localhost:3000/callback';
    // Register state before building the URL — flowStore.consume() needs it.
    const state = randomBytes(16).toString('hex');
    this.flowStore.register(state, codeVerifier);

    const authUrl = new URL(discovery.authorization_endpoint);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('client_id', this.config.clientId);
    authUrl.searchParams.set('redirect_uri', redirectUri);
    authUrl.searchParams.set('scope', 'openid profile');
    authUrl.searchParams.set('code_challenge', codeChallenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');
    authUrl.searchParams.set('state', state);

    const authRes = await fetch(authUrl.toString(), {
      redirect: 'manual',
      headers: { 'X-Session-ID': sessionId },
    });

    const location = authRes.headers.get('location');
    if (!location) {
      throw new AuthUnavailableError(`Authorize did not redirect (HTTP ${authRes.status})`);
    }

    const callbackUrl = new URL(location, this.config.tenantUrl);
    const code = callbackUrl.searchParams.get('code');
    if (!code) {
      const error = callbackUrl.searchParams.get('error');
      throw new AuthUnavailableError(`No code in redirect: ${error ?? location}`);
    }

    return this._exchangeCodeWithToken(code, state, codeVerifier);
  }
}
