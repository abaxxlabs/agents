import { describe, it, expect } from 'vitest';
import { resolveRevocationStoreKind } from '../../packages/server/src/revocation-resolution.js';

describe('packages/server resolveRevocationStoreKind', () => {
  // ─── auto resolution ────────────────────────────────────────────────────────

  describe('REVOCATION_STORE=auto (default)', () => {
    it('auto + DATABASE_URL set → postgres (production-correct multi-instance default)', () => {
      expect(
        resolveRevocationStoreKind({
          REVOCATION_STORE: 'auto',
          DATABASE_URL: 'postgresql://postgres:postgres@localhost:5432/db',
        }),
      ).toBe('postgres');
    });

    it('auto + DATABASE_URL unset → memory (dev-mode, zero-config)', () => {
      expect(resolveRevocationStoreKind({ REVOCATION_STORE: 'auto' })).toBe('memory');
    });

    it('REVOCATION_STORE unset (defaults to auto) + DATABASE_URL set → postgres', () => {
      expect(resolveRevocationStoreKind({ DATABASE_URL: 'postgresql://x:y@h:5432/d' })).toBe(
        'postgres',
      );
    });

    it('REVOCATION_STORE unset + DATABASE_URL unset → memory', () => {
      expect(resolveRevocationStoreKind({})).toBe('memory');
    });
  });

  // ─── explicit overrides ─────────────────────────────────────────────────────

  describe('REVOCATION_STORE explicit override', () => {
    it('explicit memory ignores DATABASE_URL (operator opt-out into ephemeral)', () => {
      // Explicit knob to opt into ephemeral revocation — e.g. dev-mode or
      // known-ephemeral testing. Even with DATABASE_URL set, memory wins.
      expect(
        resolveRevocationStoreKind({
          REVOCATION_STORE: 'memory',
          DATABASE_URL: 'postgresql://x:y@h:5432/d',
        }),
      ).toBe('memory');
    });

    it('explicit postgres ignores DATABASE_URL absence', () => {
      // Kind resolution doesn't probe connectivity; that happens later in
      // composeRevocationInjection. Operator is responsible for connection details.
      expect(resolveRevocationStoreKind({ REVOCATION_STORE: 'postgres' })).toBe('postgres');
    });

    it('explicit sqlite always wins', () => {
      expect(
        resolveRevocationStoreKind({
          REVOCATION_STORE: 'sqlite',
          DATABASE_URL: 'postgresql://x:y@h:5432/d',
        }),
      ).toBe('sqlite');
    });
  });

  // ─── default-arg behavior (production call shape) ──────────────────────────

  it('called without arguments, reads process.env (production behavior)', () => {
    // The production call site passes no argument; verify that path works.
    // Only assert that the result is one of the valid kinds — the test
    // environment's process.env is whatever vitest set it to.
    const result = resolveRevocationStoreKind();
    expect(['memory', 'postgres', 'sqlite']).toContain(result);
  });
});
