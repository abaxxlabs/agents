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
 * packages/server REVOCATION_STORE auto-detection.
 *
 * Pins the resolution contract:
 *   - `REVOCATION_STORE` unset OR `auto` + `DATABASE_URL` set → `postgres`
 *   - `REVOCATION_STORE` unset OR `auto` + `DATABASE_URL` unset → `memory`
 *   - `REVOCATION_STORE=memory` → `memory` (regardless of DATABASE_URL)
 *   - `REVOCATION_STORE=postgres` → `postgres`
 *   - `REVOCATION_STORE=sqlite` → `sqlite`
 *
 * `resolveRevocationStoreKind` is pure (env in, kind out), so a unit test
 * pins the contract without the overhead of booting the full server process.
 * `composeRevocationInjection` consumes the kind verbatim, so pinning the
 * kind pins the whole chain.
 */

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
