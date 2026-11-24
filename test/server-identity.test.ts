import { describe, it, expect, beforeEach } from 'vitest';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomBytes } from 'node:crypto';
import { JsonFileBackend } from '#identity/keystore.js';
import { initializeServerIdentity, rotateServerIdentity } from '#identity/server-identity.js';

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

  it('generates a did:key DID on first run', async () => {
    const identity = await initializeServerIdentity(keystore);
    expect(identity.did).toMatch(/^did:key:z[1-9A-HJ-NP-Za-km-z]+$/);
    expect(identity.isNew).toBe(true);
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
});
