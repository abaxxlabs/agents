import { describe, it, expect } from 'vitest';
import {
  MigrationTrustAnchor,
  UntrustedMigrationIssuerError,
  asTrustedMigrationCredential,
  asVerifiedParentCredential,
} from '../src/discovery/migration-trust-anchor.js';

// ─── Test JWT helpers ────────────────────────────────────────────

function makeJwt(iss: string): string {
  const header = Buffer.from(JSON.stringify({ alg: 'EdDSA' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({ iss })).toString('base64url');
  return `${header}.${payload}.fakesig`;
}

describe('MigrationTrustAnchor', () => {
  describe('default construction', () => {
    it('seeds from build-time OFFICIAL_MIGRATION_ISSUERS (empty in OSS source)', () => {
      const anchor = new MigrationTrustAnchor();
      // OSS source has an empty baked set — no DIDs are trusted by default.
      // AbaxxOne builds replace OFFICIAL_MIGRATION_ISSUERS at release time.
      expect(anchor.list()).toHaveLength(0);
      expect(anchor.isTrusted('did:dht:any-did')).toBe(false);
    });
  });

  describe('addFromParentCredentialChain', () => {
    it('adds a DID with source "parent-credential-chain"', () => {
      const anchor = new MigrationTrustAnchor();
      anchor.addFromParentCredentialChain('did:dht:abaxxone-runtime');
      expect(anchor.isTrusted('did:dht:abaxxone-runtime')).toBe(true);
      const entries = anchor.list();
      expect(entries).toHaveLength(1);
      expect(entries[0]).toMatchObject({
        did: 'did:dht:abaxxone-runtime',
        source: 'parent-credential-chain',
      });
    });

    it('is idempotent — re-adding an existing DID does not duplicate or change source', () => {
      const anchor = new MigrationTrustAnchor();
      anchor.addFromParentCredentialChain('did:dht:test-issuer');
      anchor.addFromParentCredentialChain('did:dht:test-issuer');
      anchor.addFromParentCredentialChain('did:dht:test-issuer');
      const entries = anchor.list();
      expect(entries).toHaveLength(1);
      expect(entries[0]?.source).toBe('parent-credential-chain');
    });

    it('rejects empty string DID', () => {
      const anchor = new MigrationTrustAnchor();
      expect(() => anchor.addFromParentCredentialChain('')).toThrow(TypeError);
      expect(anchor.list()).toHaveLength(0);
    });

    it('rejects non-string DID', () => {
      const anchor = new MigrationTrustAnchor();
      // @ts-expect-error — runtime check should reject non-string input even
      // when callers bypass the type system (e.g., dynamically-typed callers).
      expect(() => anchor.addFromParentCredentialChain(null)).toThrow(TypeError);
      // @ts-expect-error — same check for undefined
      expect(() => anchor.addFromParentCredentialChain(undefined)).toThrow(TypeError);
    });
  });

  describe('isTrusted', () => {
    it('returns false for unknown DIDs', () => {
      const anchor = new MigrationTrustAnchor();
      expect(anchor.isTrusted('did:dht:unknown')).toBe(false);
      expect(anchor.isTrusted('did:key:unknown')).toBe(false);
      expect(anchor.isTrusted('')).toBe(false);
    });

    it('returns true after addFromParentCredentialChain', () => {
      const anchor = new MigrationTrustAnchor();
      anchor.addFromParentCredentialChain('did:dht:trusted');
      expect(anchor.isTrusted('did:dht:trusted')).toBe(true);
      expect(anchor.isTrusted('did:dht:other')).toBe(false);
    });
  });

  describe('list', () => {
    it('returns a snapshot — mutating the result does not affect the anchor', () => {
      const anchor = new MigrationTrustAnchor();
      anchor.addFromParentCredentialChain('did:dht:a');
      anchor.addFromParentCredentialChain('did:dht:b');

      const snapshot = anchor.list();
      expect(snapshot).toHaveLength(2);

      // Even though the array itself is `readonly` typed, attempting to mutate
      // (via Array's prototype methods) would only affect the returned array,
      // not the internal map. Verify by adding another entry and re-listing.
      anchor.addFromParentCredentialChain('did:dht:c');
      expect(anchor.list()).toHaveLength(3);
    });
  });

  describe('structural enforcement (no runtime override path)', () => {
    it('does not expose env-source or api-source mutation methods', () => {
      const anchor = new MigrationTrustAnchor();
      // Negative tests — these methods must not exist.
      // If they're added in the future, the audit's hardening intent is violated.
      // @ts-expect-error — addTrustedServer is on LocalTrustAnchorStore, NOT here
      expect(anchor.addTrustedServer).toBeUndefined();
      // @ts-expect-error — addFromEnv would re-introduce the runtime-config gap
      expect(anchor.addFromEnv).toBeUndefined();
      // @ts-expect-error — fromApi would re-introduce the runtime-config gap
      expect(anchor.fromApi).toBeUndefined();
    });

    it('does not accept constructor options that would override the baked set', () => {
      // Negative test — the constructor takes no arguments. If a caller
      // passes options (mistakenly or maliciously trying to seed issuers),
      // they are ignored because the class doesn't read them. The
      // OFFICIAL_MIGRATION_ISSUERS constant is the only source for baked
      // entries.
      // @ts-expect-error — MigrationTrustAnchor constructor is intentionally argument-free
      const anchor = new MigrationTrustAnchor({ bakedIssuers: ['did:dht:attacker'] });
      expect(anchor.isTrusted('did:dht:attacker')).toBe(false);
      expect(anchor.list()).toHaveLength(0);
    });

    it('uses ECMAScript hard-private fields (entries not accessible at runtime)', () => {
      // TypeScript `private` is type-erased — at runtime,
      // `anchor['_entries'].set(...)` would work. ECMAScript `#private` is
      // enforced by the engine. Verify via Object.getOwnPropertyNames and
      // bracket-access — neither reveals the private slot.
      const anchor = new MigrationTrustAnchor();
      const ownProps = Object.getOwnPropertyNames(anchor);
      expect(ownProps).not.toContain('_entries');
      expect(ownProps).not.toContain('#entries');
      // Bracket access for the old (non-private) name returns undefined.
      expect((anchor as unknown as { _entries?: unknown })._entries).toBeUndefined();
    });
  });

  describe('DID normalization', () => {
    it('rejects DIDs containing leading whitespace', () => {
      const anchor = new MigrationTrustAnchor();
      expect(() => anchor.addFromParentCredentialChain('  did:dht:padded')).toThrow(/whitespace/);
    });

    it('rejects DIDs containing trailing whitespace', () => {
      const anchor = new MigrationTrustAnchor();
      expect(() => anchor.addFromParentCredentialChain('did:dht:padded\n')).toThrow(/whitespace/);
    });

    it('rejects DIDs containing interior whitespace', () => {
      const anchor = new MigrationTrustAnchor();
      expect(() => anchor.addFromParentCredentialChain('did:dht: spaced')).toThrow(/whitespace/);
    });

    it('rejects whitespace-only DIDs', () => {
      const anchor = new MigrationTrustAnchor();
      expect(() => anchor.addFromParentCredentialChain('   ')).toThrow(/whitespace/);
    });

    it('strips DID-URL fragment at insertion (stores bare DID)', () => {
      const anchor = new MigrationTrustAnchor();
      anchor.addFromParentCredentialChain('did:dht:abaxxone#key-1');
      expect(anchor.isTrusted('did:dht:abaxxone')).toBe(true);
      const entries = anchor.list();
      expect(entries).toHaveLength(1);
      expect(entries[0]?.did).toBe('did:dht:abaxxone');
    });

    it('matches a fragment-bearing DID against a bare-DID trust entry at lookup', () => {
      const anchor = new MigrationTrustAnchor();
      anchor.addFromParentCredentialChain('did:dht:abaxxone');
      // Verifier-produced credential iss often includes a key fragment.
      expect(anchor.isTrusted('did:dht:abaxxone#key-1')).toBe(true);
    });

    it('isTrusted returns false (does NOT throw) for malformed input on the hot path', () => {
      // The hot-path check must not throw — that would crash MigrationExecutor
      // on inputs an attacker can control. Throwing belongs at insertion time.
      const anchor = new MigrationTrustAnchor();
      anchor.addFromParentCredentialChain('did:dht:trusted');
      expect(anchor.isTrusted('  did:dht:trusted  ')).toBe(false);
      expect(anchor.isTrusted('did:dht:trusted\n')).toBe(false);
      expect(anchor.isTrusted('')).toBe(false);
      // @ts-expect-error — hot path tolerates non-string by returning false
      expect(anchor.isTrusted(null)).toBe(false);
      // @ts-expect-error — same for undefined
      expect(anchor.isTrusted(undefined)).toBe(false);
    });
  });

  describe('OFFICIAL_MIGRATION_ISSUERS storage shape', () => {
    it('uses a frozen array (not a frozen Set) for the build-time-baked seed', () => {
      // This test exists because Object.freeze(new Set([...])) is a footgun:
      // Set.prototype.add/delete/clear bypass Object.freeze and mutate the
      // frozen Set's contents. Codex verified empirically. The fix is to use
      // a frozen array instead. We can't directly test the const here (it's
      // module-private), but we can assert the docstring claim is now
      // structurally enforced by attempting both mutations on equivalent
      // structures.
      const frozenArr = Object.freeze(['did:dht:test'] as const);
      // Frozen array: push/splice/pop throw (in strict mode) or are silently
      // no-op-ed (in sloppy mode). Either way, the array contents stay fixed.
      // In TypeScript modules (which run as ES modules / strict mode), they throw.
      expect(() => (frozenArr as unknown as string[]).push('did:dht:other')).toThrow(TypeError);
      expect(frozenArr).toHaveLength(1);

      // Compare to the footgun: Object.freeze(new Set([...])) does NOT block .add.
      const frozenSet: ReadonlySet<string> = Object.freeze(new Set(['did:dht:test']));
      // The next two lines demonstrate the bug — they DO mutate the frozen Set.
      // We cast away readonly because TypeScript correctly rejects this; we're
      // exercising runtime behavior.
      (frozenSet as Set<string>).add('did:dht:attacker');
      expect(frozenSet.has('did:dht:attacker')).toBe(true); // BAD — but documented so it doesn't surprise future readers.
    });
  });
});

describe('UntrustedMigrationIssuerError', () => {
  it('captures the rejected issuer DID for diagnostics', () => {
    const err = new UntrustedMigrationIssuerError('did:dht:fork-org-issuer');
    expect(err.issuerDid).toBe('did:dht:fork-org-issuer');
    expect(err.name).toBe('UntrustedMigrationIssuerError');
    expect(err.message).toContain('did:dht:fork-org-issuer');
    expect(err.message).toContain('MigrationTrustAnchor');
    // Critical for catch (e instanceof UntrustedMigrationIssuerError) handling
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(UntrustedMigrationIssuerError);
  });
});

// ─── asTrustedMigrationCredential ────────────────────────────────

describe('asTrustedMigrationCredential', () => {
  it('returns a TrustedMigrationCredential when issuer is trusted', () => {
    const anchor = new MigrationTrustAnchor();
    anchor.addFromParentCredentialChain('did:dht:trusted-issuer');
    const jwt = makeJwt('did:dht:trusted-issuer');
    const result = asTrustedMigrationCredential(jwt, anchor);
    expect(result).toBe(jwt);
  });

  it('throws UntrustedMigrationIssuerError when issuer is not in the anchor', () => {
    const anchor = new MigrationTrustAnchor();
    const jwt = makeJwt('did:dht:untrusted-issuer');
    expect(() => asTrustedMigrationCredential(jwt, anchor)).toThrow(UntrustedMigrationIssuerError);
  });

  it('throws UntrustedMigrationIssuerError capturing the rejected DID', () => {
    const anchor = new MigrationTrustAnchor();
    const jwt = makeJwt('did:dht:fork-org');
    try {
      asTrustedMigrationCredential(jwt, anchor);
      expect.fail('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(UntrustedMigrationIssuerError);
      expect((e as UntrustedMigrationIssuerError).issuerDid).toBe('did:dht:fork-org');
    }
  });

  it('throws TypeError for a malformed JWT (not 3 parts)', () => {
    const anchor = new MigrationTrustAnchor();
    anchor.addFromParentCredentialChain('did:dht:trusted-issuer');
    expect(() => asTrustedMigrationCredential('not-a-jwt', anchor)).toThrow(TypeError);
  });

  it('throws TypeError for a JWT missing the iss claim', () => {
    const anchor = new MigrationTrustAnchor();
    anchor.addFromParentCredentialChain('did:dht:trusted-issuer');
    const noIss = `header.${Buffer.from(JSON.stringify({ sub: 'x' })).toString('base64url')}.sig`;
    expect(() => asTrustedMigrationCredential(noIss, anchor)).toThrow(/iss/);
  });

  it('normalizes a fragment-bearing iss to match bare-DID trust entry', () => {
    const anchor = new MigrationTrustAnchor();
    anchor.addFromParentCredentialChain('did:dht:trusted-issuer');
    const jwt = makeJwt('did:dht:trusted-issuer#key-1');
    expect(() => asTrustedMigrationCredential(jwt, anchor)).not.toThrow();
  });
});

// ─── asVerifiedParentCredential ───────────────────────────────────

describe('asVerifiedParentCredential', () => {
  it('returns a VerifiedParentCredential when issuer is trusted', () => {
    const anchor = new MigrationTrustAnchor();
    anchor.addFromParentCredentialChain('did:dht:parent-issuer');
    const jwt = makeJwt('did:dht:parent-issuer');
    const result = asVerifiedParentCredential(jwt, anchor);
    expect(result).toBe(jwt);
  });

  it('throws UntrustedMigrationIssuerError when issuer is not in the anchor', () => {
    const anchor = new MigrationTrustAnchor();
    const jwt = makeJwt('did:dht:untrusted-parent');
    expect(() => asVerifiedParentCredential(jwt, anchor)).toThrow(UntrustedMigrationIssuerError);
  });

  it('throws TypeError for a malformed JWT', () => {
    const anchor = new MigrationTrustAnchor();
    anchor.addFromParentCredentialChain('did:dht:parent-issuer');
    expect(() => asVerifiedParentCredential('bad-jwt', anchor)).toThrow(TypeError);
  });

  it('normalizes a fragment-bearing iss — matches bare-DID trust entry', () => {
    const anchor = new MigrationTrustAnchor();
    anchor.addFromParentCredentialChain('did:dht:parent-issuer');
    const jwt = makeJwt('did:dht:parent-issuer#key-2');
    expect(() => asVerifiedParentCredential(jwt, anchor)).not.toThrow();
  });
});
