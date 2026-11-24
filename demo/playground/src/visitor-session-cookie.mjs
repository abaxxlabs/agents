import { createHmac, hkdfSync, timingSafeEqual } from 'node:crypto';

const VERSION = 'v1';
const MAX_TOKEN_LENGTH = 1024;
const MAX_CLOCK_SKEW_MS = 60_000;
const TOKEN_PATTERN = /^v1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/;
const SANDBOX_ID_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const COOKIE_KEY_INFO = 'agents-playground-session-cookie-v1';

/**
 * Derive the process-wide Playground cookie signing key from the master key.
 * The derivation keeps the cookie key separate from the SQLite envelope key.
 * @param {Buffer} masterKeyBuffer
 * @returns {Buffer}
 */
export function deriveVisitorSessionCookieKey(masterKeyBuffer) {
  if (!Buffer.isBuffer(masterKeyBuffer) || masterKeyBuffer.length < 32) {
    throw new TypeError('Visitor session cookie key derivation requires a 32-byte master key');
  }
  return Buffer.from(hkdfSync('sha256', masterKeyBuffer, Buffer.alloc(32, 0), COOKIE_KEY_INFO, 32));
}

/**
 * Sign and verify the visitor session cookie without consulting any replica state.
 * @param {{ key: Buffer, absoluteTtlMs: number, now?: () => number }} options
 */
export function createVisitorSessionCookie({ key, absoluteTtlMs, now = () => Date.now() }) {
  if (!Buffer.isBuffer(key) || key.length < 32) {
    throw new TypeError('Visitor session cookie requires a 32-byte signing key');
  }
  if (!Number.isSafeInteger(absoluteTtlMs) || absoluteTtlMs < 1) {
    throw new RangeError('absoluteTtlMs must be a positive safe integer');
  }
  if (typeof now !== 'function') throw new TypeError('now must be a function');

  function signatureFor(payload) {
    return createHmac('sha256', key).update(`${VERSION}.${payload}`).digest('base64url');
  }

  return {
    issue({ sandboxId, expiresAt }) {
      if (typeof sandboxId !== 'string' || !SANDBOX_ID_PATTERN.test(sandboxId)) {
        throw new TypeError('sandboxId must be a 43-character base64url identifier');
      }
      const issuedAt = now();
      const absoluteExpiry = expiresAt ?? issuedAt + absoluteTtlMs;
      if (!Number.isSafeInteger(absoluteExpiry) || absoluteExpiry <= issuedAt) {
        throw new RangeError('expiresAt must be a future safe integer timestamp');
      }
      const payload = Buffer.from(JSON.stringify({
        sid: sandboxId,
        iat: issuedAt,
        exp: absoluteExpiry,
      })).toString('base64url');
      return {
        token: `${VERSION}.${payload}.${signatureFor(payload)}`,
        issuedAt,
        expiresAt: absoluteExpiry,
      };
    },

    verify(token) {
      if (typeof token !== 'string' || token.length > MAX_TOKEN_LENGTH || !TOKEN_PATTERN.test(token)) {
        return { ok: false, reason: 'malformed' };
      }
      const [, payload, signature] = token.split('.');
      const expected = Buffer.from(signatureFor(payload));
      const provided = Buffer.from(signature);
      if (expected.length !== provided.length || !timingSafeEqual(expected, provided)) {
        return { ok: false, reason: 'signature' };
      }
      let claims;
      try {
        claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
      } catch {
        return { ok: false, reason: 'malformed' };
      }
      if (!claims || typeof claims.sid !== 'string' || !SANDBOX_ID_PATTERN.test(claims.sid) ||
        !Number.isSafeInteger(claims.iat) || !Number.isSafeInteger(claims.exp) ||
        claims.exp <= claims.iat) {
        return { ok: false, reason: 'malformed' };
      }
      const timestamp = now();
      if (claims.iat > timestamp + MAX_CLOCK_SKEW_MS) return { ok: false, reason: 'not-yet-valid' };
      if (claims.exp <= timestamp) return { ok: false, reason: 'expired' };
      return {
        ok: true,
        sandboxId: claims.sid,
        issuedAt: claims.iat,
        expiresAt: claims.exp,
      };
    },

    fingerprint(value) {
      return createHmac('sha256', key).update(`origin:${value}`).digest('hex');
    },

    close() {
      key.fill(0);
    },
  };
}
