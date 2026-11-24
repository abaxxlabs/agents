import { describe, it, expect } from 'vitest';
import {
  canonicalizeEnvelope,
  computeMac,
  verifyMac,
  deriveSessionMacKey,
  MAX_ENVELOPE_BYTES,
} from '#storage/envelope-mac.js';
import { EnvelopeTooLargeError } from '#storage/types.js';
import type { SessionEnvelope } from '#storage/types.js';
import { asMasterKey } from '#crypto/master-key.js';

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

describe('envelope-mac — MAC verification', () => {
  const macKey = deriveSessionMacKey(padMaster('test-master-key-32-bytes-padding'));

  it('accepts an intact envelope and rejects tampering or a different master key', () => {
    const env = freshEnvelope();
    const { mac } = computeMac(env, macKey);
    expect(verifyMac(env, mac, macKey)).toBe(true);
    const tampered = { ...env, oidcSubject: 'attacker-sub' };
    expect(verifyMac(tampered, mac, macKey)).toBe(false);
    const otherMacKey = deriveSessionMacKey(padMaster('other-master-key'));
    expect(verifyMac(env, mac, otherMacKey)).toBe(false);
  });
});

describe('envelope-mac — size cap', () => {
  const macKey = deriveSessionMacKey(padMaster('size-cap-test-key'));

  it('envelope whose canonical encoding exceeds MAX_ENVELOPE_BYTES throws EnvelopeTooLargeError', () => {
    // ~50 canonical bytes per group entry; 1000 entries push the total past the 32768-byte cap.
    const largeGroups: string[] = [];
    for (let i = 0; i < 1000; i++) {
      largeGroups.push('group-' + i.toString().padStart(40, 'x'));
    }
    const env = freshEnvelope({ oidcGroupClaims: largeGroups });
    const canonical = canonicalizeEnvelope(env);
    expect(canonical.length).toBeGreaterThan(MAX_ENVELOPE_BYTES);
    expect(() => computeMac(env, macKey)).toThrow(EnvelopeTooLargeError);
  });
});
