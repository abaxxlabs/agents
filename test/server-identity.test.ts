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

import { describe, it, expect, beforeEach } from 'vitest';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomBytes } from 'node:crypto';
import { JsonFileBackend } from '../src/identity/keystore.js';
import { initializeServerIdentity, rotateServerIdentity } from '../src/identity/server-identity.js';
import { VcVerifier } from '../src/vc-verifier.js';
import { InMemoryRevocationStore } from '../src/storage/memory/revocation-store.js';

function makeTempKeystore(): JsonFileBackend {
  const dir = join(tmpdir(), `server-id-test-${randomBytes(4).toString('hex')}`);
  mkdirSync(dir, { recursive: true });
  return new JsonFileBackend(join(dir, 'keystore.json'));
}

describe('initializeServerIdentity()', () => {
  let keystore: JsonFileBackend;

  beforeEach(() => {
    keystore = makeTempKeystore();
  });

  // ─── First run ────────────────────────────────────────────────────────────

  it('generates a did:key DID on first run', async () => {
    const identity = await initializeServerIdentity(keystore);
    expect(identity.did).toMatch(/^did:key:z[1-9A-HJ-NP-Za-km-z]+$/);
    expect(identity.isNew).toBe(true);
  });

  it('persists DID and private key in keystore', async () => {
    const identity = await initializeServerIdentity(keystore);
    const storedDid = await keystore.read('agents:server:did');
    const storedKey = await keystore.read('agents:server:private-key-hex');
    expect(storedDid).toBe(identity.did);
    expect(typeof storedKey).toBe('string');
    expect(storedKey!.length).toBe(64); // 32 bytes as hex
  });

  it('returns public key (32 bytes)', async () => {
    const identity = await initializeServerIdentity(keystore);
    expect(identity.publicKey).toBeInstanceOf(Uint8Array);
    expect(identity.publicKey.length).toBe(32);
  });

  it('signer can sign a JWT', async () => {
    const identity = await initializeServerIdentity(keystore);
    const jwt = await identity.signer.signJwt({ sub: 'test', iss: identity.did });
    expect(typeof jwt).toBe('string');
    const parts = jwt.split('.');
    expect(parts).toHaveLength(3);
  });

  it('signer does not expose key material', async () => {
    const identity = await initializeServerIdentity(keystore);
    const signer = identity.signer as unknown as { privateKey?: unknown; key?: unknown };
    // Ensure there's no accessible key property
    expect(signer.privateKey).toBeUndefined();
    expect(signer.key).toBeUndefined();
    expect(Object.isFrozen(signer)).toBe(true);
  });

  // ─── Subsequent runs (load from keystore) ────────────────────────────────

  it('returns same DID on second call (load from keystore)', async () => {
    const first = await initializeServerIdentity(keystore);
    const second = await initializeServerIdentity(keystore);
    expect(second.did).toBe(first.did);
    expect(second.isNew).toBe(false);
  });

  it('loaded identity can sign JWTs', async () => {
    await initializeServerIdentity(keystore); // first run — generate
    const loaded = await initializeServerIdentity(keystore); // second run — load
    const jwt = await loaded.signer.signJwt({ sub: 'test', iss: loaded.did });
    expect(jwt.split('.')).toHaveLength(3);
  });

  it('loaded identity has same public key as original', async () => {
    const original = await initializeServerIdentity(keystore);
    const loaded = await initializeServerIdentity(keystore);
    // Compare public keys byte by byte
    expect(Buffer.from(loaded.publicKey).toString('hex')).toBe(
      Buffer.from(original.publicKey).toString('hex'),
    );
  });

  // ─── VcVerifier integration ───────────────────────────────────────────────

  it('registers public key with VcVerifier when provided', async () => {
    const verifier = new VcVerifier({
      clockSkew: '30s',
      revocationStore: new InMemoryRevocationStore(),
    });
    const identity = await initializeServerIdentity(keystore, verifier);

    // Verify we can resolve the key (registerKey makes it available offline)
    const resolvedKey = await verifier.resolvePublicKey(identity.did);
    expect(resolvedKey).toBeDefined();
    expect(Buffer.from(resolvedKey).toString('hex')).toBe(
      Buffer.from(identity.publicKey).toString('hex'),
    );
  });

  it('works without verifier (no error)', async () => {
    let threw = false;
    try {
      await initializeServerIdentity(keystore); // no verifier arg
    } catch {
      threw = true;
    }
    expect(threw).toBe(false);
  });

  // ─── Edge cases ───────────────────────────────────────────────────────────

  it('generates new identity if DID exists but key is missing', async () => {
    // Write DID without corresponding private key (simulates corrupt/partial keystore)
    await keystore.write('agents:server:did', 'did:key:z6MkCorrupt');
    // Don't write 'agents:server:private-key-hex'

    const identity = await initializeServerIdentity(keystore);
    // Should generate new identity, not crash on the corrupt partial state
    expect(identity.did).toMatch(/^did:key:z/);
    expect(identity.isNew).toBe(true);
    // New DID should be different from the corrupt placeholder
    expect(identity.did).not.toBe('did:key:z6MkCorrupt');
  });
});

describe('rotateServerIdentity()', () => {
  it('generates a new DID different from the original', async () => {
    const keystore = makeTempKeystore();
    const original = await initializeServerIdentity(keystore);
    const rotated = await rotateServerIdentity(keystore);

    expect(rotated.did).toMatch(/^did:key:z/);
    expect(rotated.did).not.toBe(original.did);
    expect(rotated.isNew).toBe(true);
  });

  it('subsequent load after rotation returns new DID', async () => {
    const keystore = makeTempKeystore();
    await initializeServerIdentity(keystore);
    const rotated = await rotateServerIdentity(keystore);
    const reloaded = await initializeServerIdentity(keystore);

    expect(reloaded.did).toBe(rotated.did);
    expect(reloaded.isNew).toBe(false);
  });
});
