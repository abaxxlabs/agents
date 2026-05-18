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

import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { createServer, type Server } from 'node:http';
import { generateKeyPairSync, sign as ed25519Sign } from 'node:crypto';
import { verifyIdTokenSignature, clearJwksCache } from '../src/auth/jwks-verify.js';
import { loopbackSkipReason, shouldRunLoopbackHttpTests } from './support/integration-gates.js';

// ─── Helpers ────────────────────────────────────────────────────────────────

function base64UrlEncode(buf: Buffer | Uint8Array): string {
  return Buffer.from(buf).toString('base64url');
}

/**
 * Generate an Ed25519 keypair and return both raw keys and JWK public key format.
 */
function generateEdKey() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });
  // Raw 32-byte keys
  const rawPublic = publicKey.subarray(12);
  const rawPrivate = privateKey.subarray(16);

  // JWK format for JWKS endpoint
  const jwk = {
    kty: 'OKP',
    crv: 'Ed25519',
    x: base64UrlEncode(rawPublic),
    use: 'sig',
    kid: 'test-key-1',
  };

  return { rawPublic, rawPrivate, jwk, publicKeyDer: publicKey, privateKeyDer: privateKey };
}

/**
 * Create a JWT signed with an Ed25519 key.
 * Returns the compact JWS string.
 */
function createSignedJwt(
  payload: Record<string, unknown>,
  privateKeyDer: Buffer,
  headerOverrides?: Record<string, unknown>,
): string {
  const header = { alg: 'EdDSA', typ: 'JWT', kid: 'test-key-1', ...headerOverrides };
  const headerB64 = base64UrlEncode(Buffer.from(JSON.stringify(header)));
  const payloadB64 = base64UrlEncode(Buffer.from(JSON.stringify(payload)));
  const signingInput = `${headerB64}.${payloadB64}`;

  const sig = ed25519Sign(undefined, Buffer.from(signingInput), {
    key: privateKeyDer,
    format: 'der',
    type: 'pkcs8',
  });
  const sigB64 = base64UrlEncode(sig);

  return `${signingInput}.${sigB64}`;
}

// ─── Test JWKS Server ───────────────────────────────────────────────────────

const describeLoopback: typeof describe = shouldRunLoopbackHttpTests ? describe : describe.skip;

if (!shouldRunLoopbackHttpTests) {
  describe('Loopback HTTP integration gate', () => {
    it.skip(loopbackSkipReason, () => {});
  });
}

describeLoopback('JWKS Verify — security hardening', () => {
  let server: Server;
  let jwksUri: string;
  let currentJwks: { keys: ReturnType<typeof generateEdKey>['jwk'][] };
  const key1 = generateEdKey();
  const key2 = generateEdKey();

  beforeAll(async () => {
    // Set initial JWKS to key1
    currentJwks = { keys: [key1.jwk] };

    server = createServer((req, res) => {
      if (req.url === '/.well-known/jwks') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(currentJwks));
      } else {
        res.writeHead(404);
        res.end('Not found');
      }
    });

    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', resolve);
    });
    const addr = server.address() as { port: number };
    jwksUri = `http://127.0.0.1:${addr.port}/.well-known/jwks`;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  beforeEach(() => {
    // Reset cache and JWKS state between tests
    clearJwksCache();
    currentJwks = { keys: [key1.jwk] };
  });

  // ─── Algorithm Allowlist ──────────────────────────────────────────────────

  it('rejects JWT with alg: "none" (algorithm allowlist)', async () => {
    const jwt = createSignedJwt(
      { iss: 'test', sub: 'user', exp: Math.floor(Date.now() / 1000) + 300 },
      key1.privateKeyDer,
      { alg: 'none' },
    );

    await expect(verifyIdTokenSignature(jwt, jwksUri)).rejects.toThrow(
      'Unsupported or disallowed JWT algorithm: none',
    );
  });

  it('rejects JWT with alg: "HS256" (symmetric key confusion attack)', async () => {
    const jwt = createSignedJwt(
      { iss: 'test', sub: 'user', exp: Math.floor(Date.now() / 1000) + 300 },
      key1.privateKeyDer,
      { alg: 'HS256' },
    );

    await expect(verifyIdTokenSignature(jwt, jwksUri)).rejects.toThrow(
      'Unsupported or disallowed JWT algorithm: HS256',
    );
  });

  it('accepts JWT with alg: "EdDSA" (allowed algorithm)', async () => {
    const jwt = createSignedJwt(
      { iss: 'test', sub: 'user', exp: Math.floor(Date.now() / 1000) + 300 },
      key1.privateKeyDer,
    );

    // Should succeed — EdDSA is in the allowlist, key1 is in the JWKS
    const payload = await verifyIdTokenSignature(jwt, jwksUri);
    expect(payload.iss).toBe('test');
  });

  // ─── Mandatory exp Claim ──────────────────────────────────────────────────

  it('rejects JWT without exp claim', async () => {
    const jwt = createSignedJwt(
      { iss: 'test', sub: 'user', iat: Math.floor(Date.now() / 1000) },
      key1.privateKeyDer,
    );

    await expect(verifyIdTokenSignature(jwt, jwksUri)).rejects.toThrow(
      'id_token is missing required exp claim',
    );
  });

  // ─── Cache-Bust Retry on Signature Failure ────────────────────────────────

  it('retries with fresh JWKS when signature fails (key rotation)', async () => {
    // Start with key1 in the JWKS, sign a JWT with key2.
    // The first verification attempt should fail, but the retry should
    // fetch fresh JWKS (now containing key2) and succeed.

    // Step 1: Pre-populate cache with key1
    const warmupJwt = createSignedJwt(
      { iss: 'test', sub: 'warmup', exp: Math.floor(Date.now() / 1000) + 300 },
      key1.privateKeyDer,
    );
    await verifyIdTokenSignature(warmupJwt, jwksUri);

    // Step 2: Rotate — update the JWKS to serve key2 (same kid)
    currentJwks = { keys: [{ ...key2.jwk, kid: 'test-key-1' }] };

    // Step 3: Sign a JWT with key2 (same kid as key1)
    const rotatedJwt = createSignedJwt(
      { iss: 'test', sub: 'rotated', exp: Math.floor(Date.now() / 1000) + 300 },
      key2.privateKeyDer,
    );

    // Step 4: Verify — should succeed because the retry fetches the fresh JWKS with key2
    const payload = await verifyIdTokenSignature(rotatedJwt, jwksUri);
    expect(payload.sub).toBe('rotated');
  });

  it('retries with fresh JWKS when kid is not found (new key added)', async () => {
    // Pre-populate cache with key1
    const warmupJwt = createSignedJwt(
      { iss: 'test', sub: 'warmup', exp: Math.floor(Date.now() / 1000) + 300 },
      key1.privateKeyDer,
    );
    await verifyIdTokenSignature(warmupJwt, jwksUri);

    // Add key2 with a different kid
    const key2WithNewKid = { ...key2.jwk, kid: 'rotated-key-2' };
    currentJwks = { keys: [key1.jwk, key2WithNewKid] };

    // Sign with key2, using the new kid
    const newKeyJwt = createSignedJwt(
      { iss: 'test', sub: 'new-key', exp: Math.floor(Date.now() / 1000) + 300 },
      key2.privateKeyDer,
      { kid: 'rotated-key-2' },
    );

    // Should succeed — kid-not-found triggers cache bust, finds key2
    const payload = await verifyIdTokenSignature(newKeyJwt, jwksUri);
    expect(payload.sub).toBe('new-key');
  });

  // ─── Claims Validation ────────────────────────────────────────────────────

  it('validates expectedIssuer', async () => {
    const jwt = createSignedJwt(
      { iss: 'wrong-issuer', sub: 'user', exp: Math.floor(Date.now() / 1000) + 300 },
      key1.privateKeyDer,
    );

    await expect(
      verifyIdTokenSignature(jwt, jwksUri, { expectedIssuer: 'correct-issuer' }),
    ).rejects.toThrow('id_token issuer mismatch');
  });

  it('validates expectedAudience', async () => {
    const jwt = createSignedJwt(
      { iss: 'test', sub: 'user', aud: 'other-client', exp: Math.floor(Date.now() / 1000) + 300 },
      key1.privateKeyDer,
    );

    await expect(
      verifyIdTokenSignature(jwt, jwksUri, { expectedAudience: 'my-client' }),
    ).rejects.toThrow('id_token audience does not include expected client');
  });
});
