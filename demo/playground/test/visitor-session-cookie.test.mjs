import assert from 'node:assert/strict';
import test from 'node:test';
import {
  createVisitorSessionCookie,
  deriveVisitorSessionCookieKey,
} from '../src/visitor-session-cookie.mjs';

const SANDBOX_ID = 'a'.repeat(43);
const masterKey = Buffer.from('ab'.repeat(32), 'hex');

function cookieFixture({ now = 1_000_000, absoluteTtlMs = 60_000, key = Buffer.alloc(32, 3) } = {}) {
  let clock = now;
  const codec = createVisitorSessionCookie({ key, absoluteTtlMs, now: () => clock });
  return {
    codec,
    advance(ms) { clock += ms; },
    get now() { return clock; },
  };
}

test('issues a signed token that verifies without replica state', () => {
  const { codec } = cookieFixture();
  const issued = codec.issue({ sandboxId: SANDBOX_ID });

  assert.match(issued.token, /^v1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/);
  assert.equal(issued.issuedAt, 1_000_000);
  assert.equal(issued.expiresAt, 1_060_000);
  assert.deepEqual(codec.verify(issued.token), {
    ok: true,
    sandboxId: SANDBOX_ID,
    issuedAt: 1_000_000,
    expiresAt: 1_060_000,
  });
});

test('rejects tampered signatures, malformed tokens and tokens from another key', () => {
  const { codec } = cookieFixture();
  const issued = codec.issue({ sandboxId: SANDBOX_ID });
  const [version, payload, signature] = issued.token.split('.');
  const tamperedSignature = `${signature.slice(0, -1)}${signature.endsWith('A') ? 'B' : 'A'}`;
  const otherKey = createVisitorSessionCookie({ key: Buffer.alloc(32, 9), absoluteTtlMs: 60_000, now: () => 1_000_000 });

  assert.deepEqual(codec.verify(`${version}.${payload}.${tamperedSignature}`), { ok: false, reason: 'signature' });
  assert.deepEqual(otherKey.verify(issued.token), { ok: false, reason: 'signature' });
  for (const token of [undefined, '', 'not-a-token', `v1.${payload}`, `v2.${payload}.${signature}`]) {
    assert.deepEqual(codec.verify(token), { ok: false, reason: 'malformed' });
  }
});

test('rejects expired and not-yet-valid tokens', () => {
  const expired = cookieFixture();
  const issued = expired.codec.issue({ sandboxId: SANDBOX_ID });
  expired.advance(60_000);
  assert.deepEqual(expired.codec.verify(issued.token), { ok: false, reason: 'expired' });

  const future = cookieFixture({ now: 1_000_000 });
  const futureToken = future.codec.issue({ sandboxId: SANDBOX_ID });
  future.advance(-120_000);
  assert.deepEqual(future.codec.verify(futureToken.token), { ok: false, reason: 'not-yet-valid' });
});

test('fingerprints origins with the signing key', () => {
  const { codec } = cookieFixture();
  const first = codec.fingerprint('127.0.0.1');
  assert.match(first, /^[0-9a-f]{64}$/);
  assert.equal(codec.fingerprint('127.0.0.1'), first);
  assert.notEqual(codec.fingerprint('127.0.0.2'), first);
  const other = createVisitorSessionCookie({
    key: Buffer.alloc(32, 4), absoluteTtlMs: 60_000, now: () => 1_000_000,
  });
  assert.notEqual(other.fingerprint('127.0.0.1'), first);
});

test('accepts an explicit reservation expiry', () => {
  const { codec } = cookieFixture();
  const issued = codec.issue({ sandboxId: SANDBOX_ID, expiresAt: 1_030_000 });
  assert.equal(issued.expiresAt, 1_030_000);
  assert.equal(codec.verify(issued.token).expiresAt, 1_030_000);
  assert.throws(() => codec.issue({ sandboxId: SANDBOX_ID, expiresAt: 999_999 }), RangeError);
});

test('derives a separate cookie key from the master key', () => {
  const derived = deriveVisitorSessionCookieKey(masterKey);
  assert.equal(derived.length, 32);
  assert.notDeepEqual(derived, masterKey);
  assert.deepEqual(deriveVisitorSessionCookieKey(masterKey), derived);
  assert.throws(() => deriveVisitorSessionCookieKey(Buffer.alloc(16)), TypeError);
  assert.throws(() => createVisitorSessionCookie({ key: Buffer.alloc(16), absoluteTtlMs: 1 }), TypeError);
  assert.throws(() => createVisitorSessionCookie({ key: Buffer.alloc(32), absoluteTtlMs: 0 }), RangeError);
});
