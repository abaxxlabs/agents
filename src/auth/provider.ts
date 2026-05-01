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
 * Generic interface for OIDC authentication providers.
 *
 * Two-method design: `parseIdentityFromToken` is pure (no I/O, testable offline);
 * `fetchUserInfo` is an explicit network call. Callers opt in to network when needed.
 * Providers validate tokens — they do NOT issue credentials. That is the binding layer's job.
 */

export interface OidcTokenResponse {
  access_token: string;
  token_type: string;
  id_token?: string;
  refresh_token?: string;
  expires_in?: number;
  scope?: string;
}

/**
 * Identity from an OIDC provider. `issuer` and `sub` are required for
 * IdentityBindingCredential issuance — without them the binding VC is non-verifiable.
 */
export interface OidcIdentity {
  /** The human's unique identifier within this provider. For AbaxxOne, a DID. */
  humanDid: string;
  /**
   * OIDC issuer URL (the `iss` claim). Required for binding VC issuance.
   * Examples: "https://accounts.google.com", "https://login.microsoftonline.com/{tid}/v2.0"
   */
  issuer: string;
  /**
   * OIDC subject identifier (the `sub` claim). Stable, unique per user per provider.
   * Required for binding VC issuance. Combined with issuer, globally unique.
   */
  sub: string;
  /** Email address — used for OrgBoundary domain extraction. */
  email?: string;
  /** Hosted domain (Google hd claim) or tenant ID (Azure tid). For org boundary. */
  org?: string;
  /** Display name. */
  name?: string;
  /** Raw claims from the token or userinfo endpoint. */
  claims: Record<string, unknown>;
}

/** Result of buildAuthorizationUrl(). Pass state and codeVerifier to exchangeCode(). */
export interface AuthorizationUrlResult {
  /** The URL to redirect the user/browser to. */
  url: string;
  /** Opaque state parameter. Pass back to exchangeCode(). Expires in 60s. */
  state: string;
  /** PKCE code verifier. Pass back to exchangeCode(). */
  codeVerifier: string;
}

/**
 * Implement this interface to add a new identity provider.
 * @see AbaxxOneOidcProvider, GenericOidcProvider
 */
export interface OidcProvider {
  /**
   * Build a PKCE S256 authorization URL for the configured provider.
   * The library generates and owns the PKCE state and code verifier.
   * Returns the URL to redirect to and the state/verifier to pass back later.
   */
  buildAuthorizationUrl(): Promise<AuthorizationUrlResult>;

  /**
   * Exchange an authorization code for tokens and return the agent's identity.
   * Calls parseIdentityFromToken internally; calls fetchUserInfo if needed.
   *
   * @param code          The authorization code from the callback.
   * @param state         The state value returned by buildAuthorizationUrl().
   * @param codeVerifier  The code verifier returned by buildAuthorizationUrl().
   */
  exchangeCode(code: string, state: string, codeVerifier: string): Promise<OidcIdentity>;

  /**
   * Pure transform: extract as much identity as possible from token claims.
   * No network I/O. Returns Partial<OidcIdentity> — some fields may be missing
   * for providers that don't embed profile claims in tokens (most generic OIDC).
   * AbaxxOne tokens carry all fields and return a complete OidcIdentity.
   *
   * This method MUST remain pure (no I/O, no async side effects) so it stays
   * testable offline. If you need the network, use fetchUserInfo().
   */
  parseIdentityFromToken(tokenResponse: OidcTokenResponse): Partial<OidcIdentity>;

  /**
   * Explicit network call: fetch full identity from the userinfo endpoint.
   * Call this after parseIdentityFromToken() when token claims are insufficient.
   * For AbaxxOne, this is optional (token claims are complete).
   * For generic OIDC, this is typically required to get org/role claims.
   *
   * @param accessToken  The access token from a completed token exchange.
   */
  fetchUserInfo(accessToken: string): Promise<OidcIdentity>;

  /**
   * The issuer URL for this provider (e.g. https://accounts.google.com).
   * Used to derive a deterministic humanDid for non-DID sub claims (see
   * GenericOidcProvider.deriveHumanDid).
   */
  readonly issuerUrl: string;
}
