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

/** OIDC authentication provider interface. Providers validate tokens; they do not issue credentials. */

export interface OidcTokenResponse {
  access_token: string;
  token_type: string;
  id_token?: string;
  refresh_token?: string;
  expires_in?: number;
  scope?: string;
}

/** Identity from an OIDC provider. `issuer` + `sub` are required for binding VC issuance. */
export interface OidcIdentity {
  /** The human's unique identifier within this provider. For AbaxxOne, a DID. */
  humanDid: string;
  /** OIDC issuer URL (`iss` claim). */
  issuer: string;
  /** OIDC subject identifier (`sub` claim). Stable, unique per user per provider. */
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

/** @see AbaxxOneOidcProvider, GenericOidcProvider */
export interface OidcProvider {
  /** Build a PKCE S256 authorization URL. Library generates and owns state + code verifier. */
  buildAuthorizationUrl(): Promise<AuthorizationUrlResult>;

  /** Exchange an authorization code for tokens and return the identity. */
  exchangeCode(code: string, state: string, codeVerifier: string): Promise<OidcIdentity>;

  /** Extract identity from token claims only. Pure (no I/O). Returns Partial when claims are incomplete. */
  parseIdentityFromToken(tokenResponse: OidcTokenResponse): Partial<OidcIdentity>;

  /** Fetch full identity from the userinfo endpoint. */
  fetchUserInfo(accessToken: string): Promise<OidcIdentity>;

  /** Issuer URL. Used for humanDid derivation in GenericOidcProvider. */
  readonly issuerUrl: string;
}
