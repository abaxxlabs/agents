import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { createServer, type Server } from 'node:http';
import { generateKeyPairSync, sign as ed25519Sign } from 'node:crypto';
import {
  verifyIdTokenSignature,
  clearJwksCache,
  IdTokenVerificationError,
} from '#auth/jwks-verify.js';
import { loopbackSkipReason, shouldRunLoopbackHttpTests } from './support/integration-gates.js';

function base64UrlEncode(buf: Buffer | Uint8Array): string {
  return Buffer.from(buf).toString('base64url');
}

function generateEdKey() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });
  const rawPublic = publicKey.subarray(12);
  const rawPrivate = privateKey.subarray(16);

  const jwk = {
    kty: 'OKP',
    crv: 'Ed25519',
    x: base64UrlEncode(rawPublic),
    use: 'sig',
    kid: 'test-key-1',
  };

  return { rawPublic, rawPrivate, jwk, publicKeyDer: publicKey, privateKeyDer: privateKey };
}

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

const describeLoopback = shouldRunLoopbackHttpTests ? describe : describe.skip;

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
    clearJwksCache();
    currentJwks = { keys: [key1.jwk] };
  });

  it('accepts a valid EdDSA token and rejects signed tokens with invalid expiry, issuer, or audience', async () => {
    const claims = {
      iss: 'test',
      sub: 'user',
      aud: 'test-client',
      exp: Math.floor(Date.now() / 1000) + 300,
    };
    const options = { expectedIssuer: claims.iss, expectedAudience: claims.aud };
    const jwt = createSignedJwt(claims, key1.privateKeyDer);

    const payload = await verifyIdTokenSignature(jwt, jwksUri, options);
    expect(payload.iss).toBe('test');

    await expect(
      verifyIdTokenSignature(
        createSignedJwt({ ...claims, exp: undefined }, key1.privateKeyDer),
        jwksUri,
        options,
      ),
    ).rejects.toThrow(IdTokenVerificationError);
    await expect(
      verifyIdTokenSignature(
        createSignedJwt({ ...claims, exp: Math.floor(Date.now() / 1000) - 60 }, key1.privateKeyDer),
        jwksUri,
        options,
      ),
    ).rejects.toThrow(IdTokenVerificationError);
    await expect(
      verifyIdTokenSignature(
        createSignedJwt({ ...claims, iss: 'other-issuer' }, key1.privateKeyDer),
        jwksUri,
        options,
      ),
    ).rejects.toThrow(IdTokenVerificationError);
    await expect(
      verifyIdTokenSignature(
        createSignedJwt({ ...claims, aud: 'other-client' }, key1.privateKeyDer),
        jwksUri,
        options,
      ),
    ).rejects.toThrow(IdTokenVerificationError);
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

  it('retries with fresh JWKS when signature fails (key rotation)', async () => {
    const warmupJwt = createSignedJwt(
      { iss: 'test', sub: 'warmup', exp: Math.floor(Date.now() / 1000) + 300 },
      key1.privateKeyDer,
    );
    await verifyIdTokenSignature(warmupJwt, jwksUri);

    currentJwks = { keys: [{ ...key2.jwk, kid: 'test-key-1' }] };

    const rotatedJwt = createSignedJwt(
      { iss: 'test', sub: 'rotated', exp: Math.floor(Date.now() / 1000) + 300 },
      key2.privateKeyDer,
    );

    const payload = await verifyIdTokenSignature(rotatedJwt, jwksUri);
    expect(payload.sub).toBe('rotated');
  });
});
