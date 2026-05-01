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
 * MockOidcServer — Local OIDC Identity Provider for testing.
 *
 * Runs in-process and supports the full authorization_code + PKCE flow.
 * Eliminates network flakiness and rate-limiting from the test suite.
 *
 * Supports:
 * - OIDC discovery at both /.well-known/openid-configuration (standard) and
 *   /.well-known/openid_configuration (AbaxxOne convention).
 * - PKCE S256 validation.
 * - Real Ed25519-signed JWTs — VcVerifier can verify them end-to-end.
 * - Programmatic login: POST /auth/login → session_id.
 * - Auto-approve: GET /auth/authorize always redirects with a code.
 *
 * Uses Node.js built-in `http` only — no extra dependencies needed in CI.
 *
 * Security: this server is intentionally insecure and must NEVER be used outside
 * test environments. NODE_ENV=test is required.
 */

import { createServer, type Server } from 'node:http';
import { createHash, randomBytes } from 'node:crypto';
import { generateDidKey, base58Encode } from '../../src/auth/index.js';
import { createJwt } from '../../src/vc-verifier.js';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface MockUser {
  /** Email address — used as login credential and email claim */
  email: string;
  /** Password for the programmatic /auth/login endpoint */
  password?: string;
  /** Extra OIDC claims merged into tokens and userinfo (e.g., hd, tid, did) */
  extraClaims?: Record<string, unknown>;
}

export interface MockOidcServerOptions {
  /**
   * Port to bind to. Defaults to 0 (OS-assigned random port — avoids port conflicts).
   * Use a fixed port (e.g., 9876) only when testing code that has a hardcoded issuer URL.
   */
  port?: number;
  /** Pre-registered users. More can be added via registerUser() after start(). */
  users?: MockUser[];
  /**
   * Token lifetime in seconds. Default 3600 (1 hour).
   * Tests that verify token expiry should set this to a small value.
   */
  tokenTtlSeconds?: number;
}

// ─── In-flight state shapes ───────────────────────────────────────────────────

interface PendingCode {
  sub: string;
  email: string;
  extraClaims: Record<string, unknown>;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  redirectUri: string;
  clientId: string;
  /** Time the code was issued (ms). Codes expire after 60s. */
  issuedAt: number;
}

interface IssuedToken {
  sub: string;
  email: string;
  extraClaims: Record<string, unknown>;
  /** Expiry time (ms) */
  expiresAt: number;
}

// ─── MockOidcServer ───────────────────────────────────────────────────────────

/**
 * Minimal OIDC Identity Provider for test and dev use.
 *
 * Supports:
 *   - Standard discovery: /.well-known/openid-configuration
 *   - AbaxxOne discovery: /.well-known/openid_configuration
 *   - JWKS endpoint: /.well-known/jwks
 *   - Authorization: GET /auth/authorize (auto-approve, PKCE S256)
 *   - Token exchange: POST /auth/token
 *   - Userinfo: GET /auth/userinfo
 *   - Programmatic login: POST /auth/login (AbaxxOne X-Session-ID flow)
 *
 * @example
 * ```typescript
 * const mock = new MockOidcServer({ users: [{ email: 'test@company.com', password: 'pw' }] });
 * const { url } = await mock.start();
 * // ... test using url as the issuerUrl/tenantUrl
 * await mock.stop();
 * ```
 */
export class MockOidcServer {
  private server!: Server;
  private _port = 0;
  private users: Map<string, MockUser> = new Map();
  private sessions: Map<string, string> = new Map(); // sessionId → email
  private pendingCodes: Map<string, PendingCode> = new Map();
  private issuedTokens: Map<string, IssuedToken> = new Map();
  private signingKey!: { privateKey: Uint8Array; publicKey: Uint8Array; did: string };
  private tokenTtlSeconds: number;

  constructor(options: MockOidcServerOptions = {}) {
    this.tokenTtlSeconds = options.tokenTtlSeconds ?? 3600;
    this._port = options.port ?? 0;
    for (const user of options.users ?? []) {
      this.registerUser(user);
    }
  }

  // ─── Lifecycle ─────────────────────────────────────────────────

  /**
   * Start the server and begin listening.
   * @returns { url } — base URL (e.g., 'http://localhost:52341')
   */
  async start(): Promise<{ url: string }> {
    // Generate a fresh Ed25519 key pair for signing tokens.
    // Using generateDidKey() keeps us consistent with the rest of the test stack.
    this.signingKey = generateDidKey();

    return new Promise((resolve, reject) => {
      this.server = createServer((req, res) => {
        this.handleRequest(req, res).catch((err) => {
          console.error('[MockOidcServer] Unhandled error:', err);
          res.writeHead(500).end(JSON.stringify({ error: 'internal_error' }));
        });
      });

      this.server.on('error', reject);
      this.server.listen(this._port, '127.0.0.1', () => {
        const addr = this.server.address() as { port: number };
        this._port = addr.port;
        resolve({ url: this.url });
      });
    });
  }

  /** Stop the server. Safe to call multiple times. */
  async stop(): Promise<void> {
    return new Promise((resolve) => {
      if (!this.server) return resolve();
      this.server.close(() => resolve());
    });
  }

  /** Base URL of the running server (e.g., 'http://localhost:52341') */
  get url(): string {
    return `http://127.0.0.1:${this._port}`;
  }

  /** Port the server is listening on. 0 before start() is called. */
  get port(): number {
    return this._port;
  }

  // ─── User Management ───────────────────────────────────────────

  /**
   * Register a user. Can be called before or after start().
   * extraClaims are merged into id_token and userinfo responses.
   * Common examples:
   *   { hd: 'company.com' }          — Google Workspace hd claim
   *   { tid: 'azure-tenant-guid' }   — Azure AD tenant ID
   *   { did: 'did:key:z6Mk...' }     — AbaxxOne DID claim
   */
  registerUser(user: MockUser): void {
    this.users.set(user.email, user);
  }

  // ─── HTTP Request Handling ──────────────────────────────────────

  private async handleRequest(
    req: import('node:http').IncomingMessage,
    res: import('node:http').ServerResponse,
  ): Promise<void> {
    const url = new URL(req.url ?? '/', this.url);
    const path = url.pathname;
    const method = req.method ?? 'GET';

    // ── OIDC Discovery (both standard and AbaxxOne paths) ──
    if (
      path === '/.well-known/openid-configuration' ||
      path === '/.well-known/openid_configuration'
    ) {
      return this.serveDiscovery(res);
    }

    // ── JWKS ──
    if (path === '/.well-known/jwks') {
      return this.serveJwks(res);
    }

    // ── Authorization endpoint ──
    if (path === '/auth/authorize' && method === 'GET') {
      return this.handleAuthorize(url, req, res);
    }

    // ── Token endpoint ──
    if (path === '/auth/token' && method === 'POST') {
      const body = await readBody(req);
      return this.handleToken(body, res);
    }

    // ── Userinfo endpoint ──
    if (path === '/auth/userinfo' && method === 'GET') {
      return this.handleUserinfo(req, res);
    }

    // ── Programmatic login (AbaxxOne X-Session-ID flow) ──
    if (path === '/auth/login' && method === 'POST') {
      const body = await readBody(req);
      return this.handleLogin(body, res);
    }

    // ── 404 ──
    json(res, 404, { error: 'not_found', path });
  }

  // ─── Endpoint Handlers ─────────────────────────────────────────

  /**
   * OIDC discovery document. Both openid-configuration and openid_configuration
   * paths return this — the only difference is naming convention between providers.
   *
   * jwks_uri, authorization_endpoint, token_endpoint, userinfo_endpoint all point
   * to this same server so tests don't need to configure separate URLs.
   */
  private serveDiscovery(res: import('node:http').ServerResponse): void {
    const base = this.url;
    json(res, 200, {
      issuer: base,
      authorization_endpoint: `${base}/auth/authorize`,
      token_endpoint: `${base}/auth/token`,
      userinfo_endpoint: `${base}/auth/userinfo`,
      jwks_uri: `${base}/.well-known/jwks`,
      response_types_supported: ['code'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['EdDSA'],
      scopes_supported: ['openid', 'profile', 'email'],
      token_endpoint_auth_methods_supported: ['client_secret_post', 'none'],
      code_challenge_methods_supported: ['S256', 'plain'],
      grant_types_supported: ['authorization_code'],
    });
  }

  /**
   * JWKS endpoint — exposes the server's Ed25519 public key in JWK format.
   * VcVerifier uses this when verifying tokens issued by this server.
   *
   * Key type OKP + curve Ed25519 per RFC 8037.
   * kid is the first 8 chars of the DID (stable, unique enough for tests).
   */
  private serveJwks(res: import('node:http').ServerResponse): void {
    const pub = this.signingKey.publicKey;
    // OKP JWK for Ed25519: x is the base64url-encoded raw 32-byte public key
    const x = Buffer.from(pub).toString('base64url');
    json(res, 200, {
      keys: [
        {
          kty: 'OKP',
          crv: 'Ed25519',
          x,
          use: 'sig',
          alg: 'EdDSA',
          kid: this.signingKey.did.slice(8, 16), // short stable kid for tests
        },
      ],
    });
  }

  /**
   * Authorization endpoint — auto-approves all requests.
   *
   * In a real OIDC server this would show a login page. The mock skips that
   * entirely: it immediately redirects with a fresh auth code.
   *
   * For the programmatic (X-Session-ID) flow, the session must exist in this.sessions.
   * For standard browser redirect flows (no X-Session-ID), uses the first registered
   * user as the subject. Tests should call registerUser() to set up the desired identity
   * before triggering the authorization flow.
   *
   * PKCE: stores code_challenge (S256 or plain) alongside the code.
   * Validated later in handleToken().
   */
  private handleAuthorize(
    url: URL,
    req: import('node:http').IncomingMessage,
    res: import('node:http').ServerResponse,
  ): void {
    // Resolve which user to auto-approve
    const sessionId = req.headers['x-session-id'] as string | undefined;
    let email: string | undefined;

    if (sessionId) {
      email = this.sessions.get(sessionId);
      if (!email) {
        json(res, 401, { error: 'invalid_session', description: 'Session not found' });
        return;
      }
    } else {
      // No session — use default user (first registered or 'test@mock.local')
      email = this.users.keys().next().value ?? 'test@mock.local';
    }

    const user = this.users.get(email!) ?? { email: email! };
    const redirectUri = url.searchParams.get('redirect_uri') ?? 'http://localhost:3000/callback';
    const clientId = url.searchParams.get('client_id') ?? 'mock-client';
    const codeChallenge = url.searchParams.get('code_challenge') ?? undefined;
    const codeChallengeMethod = url.searchParams.get('code_challenge_method') ?? undefined;
    const state = url.searchParams.get('state');

    // Issue a one-time auth code (expires after 60s)
    const code = randomBytes(16).toString('base64url');
    this.pendingCodes.set(code, {
      sub: email!,
      email: email!,
      extraClaims: user.extraClaims ?? {},
      codeChallenge,
      codeChallengeMethod,
      redirectUri,
      clientId,
      issuedAt: Date.now(),
    });

    // Redirect to callback with code (+ state for CSRF if provided)
    const cb = new URL(redirectUri);
    cb.searchParams.set('code', code);
    if (state) cb.searchParams.set('state', state);

    res.writeHead(302, { Location: cb.toString() });
    res.end();
  }

  /**
   * Token endpoint — exchanges an auth code for access_token + id_token.
   *
   * PKCE validation: if code_challenge was stored with the code, verifies that
   * sha256(code_verifier) === code_challenge (S256) or code_verifier === code_challenge (plain).
   * This ensures the PKCE flow is actually tested end-to-end.
   *
   * Both tokens are real Ed25519-signed JWTs using createJwt() so VcVerifier can
   * verify them without special mocking.
   */
  private handleToken(body: URLSearchParams | null, res: import('node:http').ServerResponse): void {
    if (!body) {
      json(res, 400, { error: 'invalid_request', description: 'Empty body' });
      return;
    }

    const code = body.get('code');
    const codeVerifier = body.get('code_verifier') ?? undefined;
    const grantType = body.get('grant_type');

    if (grantType !== 'authorization_code') {
      json(res, 400, { error: 'unsupported_grant_type' });
      return;
    }

    if (!code) {
      json(res, 400, { error: 'invalid_request', description: 'Missing code' });
      return;
    }

    const pending = this.pendingCodes.get(code);
    if (!pending) {
      json(res, 400, { error: 'invalid_grant', description: 'Code not found or expired' });
      return;
    }

    // Expire codes after 60s
    if (Date.now() - pending.issuedAt > 60_000) {
      this.pendingCodes.delete(code);
      json(res, 400, { error: 'invalid_grant', description: 'Code expired' });
      return;
    }

    this.pendingCodes.delete(code); // one-time use

    // PKCE validation
    if (pending.codeChallenge) {
      if (!codeVerifier) {
        json(res, 400, { error: 'invalid_grant', description: 'code_verifier required (PKCE)' });
        return;
      }
      const method = pending.codeChallengeMethod ?? 'S256';
      let computed: string;
      if (method === 'S256') {
        computed = createHash('sha256').update(codeVerifier).digest('base64url');
      } else {
        // plain
        computed = codeVerifier;
      }
      if (computed !== pending.codeChallenge) {
        json(res, 400, { error: 'invalid_grant', description: 'PKCE code_verifier mismatch' });
        return;
      }
    }

    // Issue tokens
    const now = Math.floor(Date.now() / 1000);
    const exp = now + this.tokenTtlSeconds;

    const baseClaims = {
      iss: this.url,
      sub: pending.sub,
      aud: pending.clientId,
      iat: now,
      exp,
      email: pending.email,
      ...pending.extraClaims,
    };

    const idToken = createJwt(baseClaims, this.signingKey.privateKey);
    const accessToken = randomBytes(24).toString('base64url'); // opaque access token

    // Record for userinfo lookups
    this.issuedTokens.set(accessToken, {
      sub: pending.sub,
      email: pending.email,
      extraClaims: pending.extraClaims,
      expiresAt: exp * 1000,
    });

    json(res, 200, {
      access_token: accessToken,
      id_token: idToken,
      token_type: 'Bearer',
      expires_in: this.tokenTtlSeconds,
    });
  }

  /**
   * Userinfo endpoint — returns the claims associated with the access token.
   *
   * AbaxxOne userinfo includes a `did` field. The mock generates a deterministic
   * did:key for each user based on their email, so the same user always gets the
   * same DID across test runs (important for binding tests).
   *
   * Standard OIDC providers return { sub, email, name, ...extraClaims }.
   */
  private handleUserinfo(
    req: import('node:http').IncomingMessage,
    res: import('node:http').ServerResponse,
  ): void {
    const authHeader = req.headers.authorization ?? '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

    if (!token) {
      res.writeHead(401, { 'WWW-Authenticate': 'Bearer realm="mock"' });
      res.end(JSON.stringify({ error: 'invalid_token' }));
      return;
    }

    const tokenData = this.issuedTokens.get(token);
    if (!tokenData || Date.now() > tokenData.expiresAt) {
      res.writeHead(401);
      res.end(JSON.stringify({ error: 'invalid_token' }));
      return;
    }

    // Derive a deterministic DID for this user from their email
    // (stable across test runs — same email always produces same DID seed)
    const emailDid = deriveDidFromEmail(tokenData.email);

    json(res, 200, {
      sub: tokenData.sub,
      email: tokenData.email,
      name: tokenData.email.split('@')[0],
      // AbaxxOne-style DID claim — GenericOidcProvider ignores this, AbaxxOneOidcProvider uses it
      did: emailDid,
      ...tokenData.extraClaims,
    });
  }

  /**
   * Programmatic login endpoint — POST /auth/login.
   *
   * Returns a session_id that can be used with X-Session-ID header in GET /auth/authorize.
   * This is the AbaxxOne CLI flow (loginProgrammatic).
   *
   * Security: validates password against registered users. Unknown emails or wrong
   * passwords return 401. This is intentionally simple — tests should pre-register
   * users via registerUser() with known passwords.
   */
  private handleLogin(body: URLSearchParams | null, res: import('node:http').ServerResponse): void {
    // Body can be JSON or form-encoded
    const email = body?.get('email');
    const password = body?.get('password');

    if (!email || !password) {
      json(res, 400, { error: 'invalid_request', description: 'email and password required' });
      return;
    }

    const user = this.users.get(email);
    if (!user || (user.password && user.password !== password)) {
      json(res, 401, { error: 'invalid_credentials', description: 'Invalid email or password' });
      return;
    }

    const sessionId = randomBytes(24).toString('base64url');
    this.sessions.set(sessionId, email);

    // Sessions expire after 5 minutes — clean up old ones periodically
    setTimeout(() => this.sessions.delete(sessionId), 5 * 60 * 1000);

    json(res, 200, { session_id: sessionId });
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Read and parse the request body as application/x-www-form-urlencoded or JSON.
 * Returns null if the body is empty or unparseable.
 */
async function readBody(req: import('node:http').IncomingMessage): Promise<URLSearchParams | null> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8').trim();
      if (!raw) return resolve(null);
      try {
        // Try JSON first (POST /auth/login uses JSON in tests)
        const parsed = JSON.parse(raw);
        const params = new URLSearchParams();
        for (const [k, v] of Object.entries(parsed)) {
          params.set(k, String(v));
        }
        resolve(params);
      } catch {
        // Fall back to form-encoded
        try {
          resolve(new URLSearchParams(raw));
        } catch {
          resolve(null);
        }
      }
    });
    req.on('error', () => resolve(null));
  });
}

/**
 * Write a JSON response with the given status code.
 */
function json(res: import('node:http').ServerResponse, status: number, body: unknown): void {
  const data = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(data),
    'Cache-Control': 'no-store',
  });
  res.end(data);
}

/**
 * Derive a deterministic did:key from an email address.
 * Used to give each mock user a stable DID for binding tests.
 *
 * Security: this is NOT a cryptographically secure DID — it's a test fixture.
 * The private key is not accessible; only the DID (public identifier) is returned.
 * Real DIDs come from generateDidKey() with a securely random key pair.
 */
function deriveDidFromEmail(email: string): string {
  // Use the email as a deterministic multicodec prefix (not a real key — test only)
  // We derive the raw key by hashing the email, then encode as a did:key
  const seed = createHash('sha256')
    .update('mock-did-seed:' + email)
    .digest();
  // Ed25519 multicodec: 0xed 0x01
  const multicodec = new Uint8Array(2 + 32);
  multicodec[0] = 0xed;
  multicodec[1] = 0x01;
  multicodec.set(seed, 2);
  return `did:key:z${base58Encode(multicodec)}`;
}
