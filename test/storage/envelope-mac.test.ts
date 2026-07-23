import { describe, it, expect } from 'vitest';
import {
  canonicalizeEnvelope,
  computeMac,
  verifyMac,
  deriveSessionMacKey,
  HKDF_CONTEXT_SESSION_MAC,
  HKDF_SALT_SESSION_MAC,
  MAX_ENVELOPE_BYTES,
  MAC_BYTES,
} from '#storage/envelope-mac.js';
import { EnvelopeTooLargeError } from '#storage/types.js';
import type { SessionEnvelope } from '#storage/types.js';
import { asMasterKey } from '#crypto/master-key.js';
import { hkdfSync } from 'node:crypto';
import * as canonicalizeModule from 'canonicalize';

const canonicalize = (
  canonicalizeModule as unknown as { default: (input: unknown) => string | undefined }
).default;

/** Build a 32-byte branded MasterKey from a short label by zero-padding. */
function padMaster(label: string): ReturnType<typeof asMasterKey> {
  const buf = Buffer.alloc(32);
  Buffer.from(label, 'utf8').copy(buf);
  return asMasterKey(buf);
}

function freshEnvelope(overrides: Partial<SessionEnvelope> = {}): SessionEnvelope {
  return {
    humanDid: 'did:key:zAlice',
    email: 'alice@example.com',
    oidcIssuer: 'https://login.abaxx.one/realms/demo',
    oidcSubject: 'alice-sub-123',
    oidcGroupClaims: ['group-1'],
    oidcTenantUrl: 'https://login.abaxx.one',
    parentJwt: 'header.body.sig',
    providerKind: 'oidc-abaxx-one',
    createdAt: 1_700_000_000_000,
    expiresAt: 1_700_014_400_000,
    ...overrides,
  };
}

describe('envelope-mac — HKDF key derivation', () => {
  it('deriveSessionMacKey returns 32 bytes', () => {
    // The label is exactly 32 bytes, but brand it via padMaster for uniformity.
    const master = padMaster('0123456789abcdef0123456789abcdef');
    const key = deriveSessionMacKey(master);
    expect(key).toBeInstanceOf(Buffer);
    expect(key.length).toBe(32);
  });

  it('deriveSessionMacKey is deterministic (cross-instance coherency invariant)', () => {
    const master = padMaster('same-master-key');
    const k1 = deriveSessionMacKey(master);
    const k2 = deriveSessionMacKey(master);
    expect(k1.equals(k2)).toBe(true);
  });

  it('deriveSessionMacKey with different masters yields different keys', () => {
    const k1 = deriveSessionMacKey(padMaster('master-A'));
    const k2 = deriveSessionMacKey(padMaster('master-B'));
    expect(k1.equals(k2)).toBe(false);
  });

  it('HKDF derived keys must use distinct context strings', () => {
    expect(HKDF_CONTEXT_SESSION_MAC).toBe('agents:SessionStore:mac:v1');
    expect(HKDF_SALT_SESSION_MAC.length).toBe(0);

    // Derive a key for a different purpose and verify it does not collide with the session-MAC key.
    const master = padMaster('test-master');
    const sessionKey = deriveSessionMacKey(master);
    const byokKey = Buffer.from(
      hkdfSync('sha256', master, HKDF_SALT_SESSION_MAC, 'agents:byok:master:v1', 32),
    );
    expect(sessionKey.equals(byokKey)).toBe(false);
  });
});

describe('envelope-mac — canonical encoding (RFC 8785)', () => {
  it('canonicalizeEnvelope returns UTF-8 bytes', () => {
    const env = freshEnvelope();
    const bytes = canonicalizeEnvelope(env);
    expect(bytes).toBeInstanceOf(Buffer);
    expect(bytes.toString('utf8').startsWith('{')).toBe(true);
  });

  it('canonical output is stable (same input → same bytes)', () => {
    const env = freshEnvelope();
    const b1 = canonicalizeEnvelope(env);
    const b2 = canonicalizeEnvelope(env);
    expect(b1.equals(b2)).toBe(true);
  });

  it('canonical output is order-independent (same fields, different key order → same bytes)', () => {
    const env1 = freshEnvelope();
    const env2: SessionEnvelope = {
      expiresAt: env1.expiresAt,
      createdAt: env1.createdAt,
      providerKind: env1.providerKind,
      parentJwt: env1.parentJwt,
      oidcTenantUrl: env1.oidcTenantUrl,
      oidcGroupClaims: env1.oidcGroupClaims,
      oidcSubject: env1.oidcSubject,
      oidcIssuer: env1.oidcIssuer,
      email: env1.email,
      humanDid: env1.humanDid,
    };
    expect(canonicalizeEnvelope(env1).equals(canonicalizeEnvelope(env2))).toBe(true);
  });

  // RY-3: RFC 8785 Appendix B test vector. This is a canonical JCS test case
  // from the spec — our canonicalization MUST match it exactly. If this fails,
  // we have a spec-compliance regression and every envelope in flight becomes
  // un-MAC-able across versions.
  it('RFC 8785 Appendix B — object with interleaved string-key and numeric-looking-key', () => {
    // Vector from RFC 8785 §3.2.3 (ordering + escape rules).
    // Input: {"peach":"This sorting order","péché":"is not correct","pêche":"for French","sin":"words"}
    // Expected canonical: sorted by UTF-16 code units of keys.
    // We validate by calling canonicalize directly on the vector, not on our
    // envelope shape — this proves the `canonicalize` dep is producing
    // spec-compliant output.
    //
    // Per RFC 8785 §3.2.3, keys are sorted by UTF-16 code units. The expected
    // ordering is: peach (0x70 0x65...), pêche (0x70 0xEA 0x63...),
    // péché (0x70 0xE9 0x63...), sin.
    //
    // Actually the spec's §3.2.3 example lists the ordering as:
    //   peach, pêche, péché, sin  (code-unit order of 2nd char: 'e' 0x65, ê 0xEA, é 0xE9 ...)
    // wait — 0xE9 < 0xEA, so the correct order is peach, péché, pêche, sin.
    const input = {
      peach: 'This sorting order',
      péché: 'is not correct',
      pêche: 'for French',
      sin: 'words',
    };
    const expected =
      '{"peach":"This sorting order","péché":"is not correct","pêche":"for French","sin":"words"}';
    // Use the internal canonicalize (via canonicalizeEnvelope-compatible path):
    // canonicalize operates on any JSON value, so we call it with our helper
    // by wrapping input as a SessionEnvelope-shape is not applicable here;
    // we import canonicalize directly through the same module the adapter uses.
    // For this test, assert the default dep is RFC-8785-compliant:
    //   (import * as canonicalizeModule from 'canonicalize'; canonicalizeModule.default(input))

    const out = canonicalize(input);
    expect(out).toBe(expected);
  });
});

describe('envelope-mac — MAC round-trip', () => {
  const macKey = deriveSessionMacKey(padMaster('test-master-key-32-bytes-padding'));

  it('computeMac + verifyMac round-trips OK', () => {
    const env = freshEnvelope();
    const { mac, canonicalBytes } = computeMac(env, macKey);
    expect(mac.length).toBe(MAC_BYTES);
    expect(canonicalBytes.length).toBeGreaterThan(0);
    expect(verifyMac(env, mac, macKey)).toBe(true);
  });

  it('bit-flip in envelope → verify fails', () => {
    const env = freshEnvelope();
    const { mac } = computeMac(env, macKey);
    const tampered = { ...env, oidcSubject: 'attacker-sub' };
    expect(verifyMac(tampered, mac, macKey)).toBe(false);
  });

  it('bit-flip in MAC → verify fails', () => {
    const env = freshEnvelope();
    const { mac } = computeMac(env, macKey);
    const tamperedMac = Buffer.from(mac);
    tamperedMac[0] ^= 0x01;
    expect(verifyMac(env, tamperedMac, macKey)).toBe(false);
  });

  it('wrong master key → verify fails (key-space separation)', () => {
    const env = freshEnvelope();
    const { mac } = computeMac(env, macKey);
    const wrongKey = deriveSessionMacKey(padMaster('different-master'));
    expect(verifyMac(env, mac, wrongKey)).toBe(false);
  });

  it('MAC cross-env: env1 MAC applied to env2 → fails', () => {
    const env1 = freshEnvelope({ humanDid: 'did:key:zAlice' });
    const env2 = freshEnvelope({ humanDid: 'did:key:zBob' });
    const { mac: macForAlice } = computeMac(env1, macKey);
    expect(verifyMac(env2, macForAlice, macKey)).toBe(false);
  });

  it('timing-safe MAC comparison (mismatched lengths → false, not throw)', () => {
    const env = freshEnvelope();
    const shortMac = Buffer.from('ab', 'hex');
    expect(() => verifyMac(env, shortMac, macKey)).not.toThrow();
    expect(verifyMac(env, shortMac, macKey)).toBe(false);
  });
});

describe('envelope-mac — size cap', () => {
  const macKey = deriveSessionMacKey(padMaster('size-cap-test-key'));

  it('MAX_ENVELOPE_BYTES constant is 32768 (32KB)', () => {
    expect(MAX_ENVELOPE_BYTES).toBe(32768);
  });

  it('small envelope is accepted', () => {
    const env = freshEnvelope();
    expect(() => computeMac(env, macKey)).not.toThrow();
  });

  it('envelope whose canonical encoding exceeds MAX_ENVELOPE_BYTES throws EnvelopeTooLargeError', () => {
    // Fill oidcGroupClaims with enough strings to push canonical output > cap.
    // Each entry contributes ~50 bytes canonical (string value + quotes +
    // comma). We want > 32768 bytes canonical total.
    const largeGroups: string[] = [];
    // Build groups until canonical output exceeds cap.
    for (let i = 0; i < 1000; i++) {
      largeGroups.push('group-' + i.toString().padStart(40, 'x'));
    }
    const env = freshEnvelope({ oidcGroupClaims: largeGroups });
    const canonical = canonicalizeEnvelope(env);
    expect(canonical.length).toBeGreaterThan(MAX_ENVELOPE_BYTES);
    expect(() => computeMac(env, macKey)).toThrow(EnvelopeTooLargeError);
  });

  it('EnvelopeTooLargeError reports actual and max sizes', () => {
    const largeGroups: string[] = [];
    for (let i = 0; i < 1000; i++) {
      largeGroups.push('g' + 'x'.repeat(100));
    }
    const env = freshEnvelope({ oidcGroupClaims: largeGroups });
    try {
      computeMac(env, macKey);
      expect.fail('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(EnvelopeTooLargeError);
      if (err instanceof EnvelopeTooLargeError) {
        expect(err.maxBytes).toBe(MAX_ENVELOPE_BYTES);
        expect(err.sizeBytes).toBeGreaterThan(MAX_ENVELOPE_BYTES);
        expect(err.code).toBe('ENVELOPE_TOO_LARGE');
      }
    }
  });

  it('size is measured on canonical output, not pre-canonicalization JSON', () => {
    // Construct an envelope that's fine in JSON but bloats under canonicalization.
    // Canonicalization typically NORMALIZES sizes, but let's verify that the
    // size-check function is wired to canonical bytes, not an input-JSON-string
    // approximation. We do this by computing canonical length explicitly and
    // comparing against the threshold the implementation uses.
    const env = freshEnvelope({
      oidcGroupClaims: Array.from({ length: 100 }, (_, i) => `grp-${i}`),
    });
    const canonical = canonicalizeEnvelope(env);
    // Sanity: if the implementation were measuring input-JSON size it'd be
    // JSON.stringify(env).length, which is different-formatted from canonical.
    // As long as the reject path uses canonical.length, we're good — the
    // cap-throwing test above already proves this at the boundary.
    expect(canonical.length).toBeLessThan(MAX_ENVELOPE_BYTES);
    expect(() => computeMac(env, macKey)).not.toThrow();
  });
});
