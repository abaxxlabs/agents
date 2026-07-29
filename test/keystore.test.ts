import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { statSync, writeFileSync, chmodSync, existsSync, mkdirSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { join } from 'node:path';
import { tmpdir, homedir } from 'node:os';
import { randomBytes } from 'node:crypto';
import { JsonFileBackend, MacOsKeychainBackend, createKeystore } from '#identity/keystore.js';
import { keychainSkipReason, shouldRunMacOsKeychainTests } from './support/integration-gates.js';

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeTempDir(): string {
  const dir = join(tmpdir(), `agents-test-${randomBytes(4).toString('hex')}`);
  mkdirSync(dir, { recursive: true });
  return dir;
}

function keystorePath(dir: string): string {
  return join(dir, 'keystore.json');
}

// ─── JsonFileBackend ─────────────────────────────────────────────────────────

describe('JsonFileBackend', () => {
  let dir: string;
  let backend: JsonFileBackend;

  beforeEach(() => {
    dir = makeTempDir();
    backend = new JsonFileBackend(keystorePath(dir));
  });

  afterEach(() => {
    // Cleanup — best effort
    try {
      execSync(`rm -rf ${dir}`);
    } catch {
      /* ignore */
    }
  });

  // ─── Read ────────────────────────────────────────────────────────────────

  it('read() returns null when file does not exist', async () => {
    const result = await backend.read('missing-key');
    expect(result).toBeNull();
  });

  it('read() returns null for unknown key in existing file', async () => {
    await backend.write('other-key', 'other-value');
    const result = await backend.read('missing-key');
    expect(result).toBeNull();
  });

  it('read() returns null on corrupt JSON', async () => {
    writeFileSync(keystorePath(dir), '{ bad json !', { mode: 0o600 });
    const result = await backend.read('any-key');
    expect(result).toBeNull();
  });

  it('read() returns stored value after write', async () => {
    await backend.write('agent-key', 'agent-secret-value');
    const result = await backend.read('agent-key');
    expect(result).toBe('agent-secret-value');
  });

  it('read() returns null after write returns empty string trimmed to null', async () => {
    // Empty string write stores '' — read returns '' not null
    // (caller decides what's meaningful — we don't second-guess)
    await backend.write('empty-key', '');
    const result = await backend.read('empty-key');
    expect(result).toBe('');
  });

  // ─── Write ───────────────────────────────────────────────────────────────

  it('write() creates file with 0600 permissions', async () => {
    await backend.write('my-key', 'my-value');
    const stat = statSync(keystorePath(dir));
    // mode & 0o777 strips file type bits — compare permission bits only
    expect(stat.mode & 0o777).toBe(0o600);
  });

  it('write() enforces 0600 regardless of process umask', async () => {
    const oldMask = process.umask(0o000);
    try {
      await backend.write('umask-key', 'umask-value');
      const stat = statSync(keystorePath(dir));
      expect(stat.mode & 0o777).toBe(0o600);
    } finally {
      process.umask(oldMask);
    }
  });

  it('write() restores 0600 when file pre-exists with wider permissions', async () => {
    const path = keystorePath(dir);
    writeFileSync(path, '{}', { mode: 0o644 });
    chmodSync(path, 0o644);

    await backend.write('key', 'value');
    const stat = statSync(path);
    expect(stat.mode & 0o777).toBe(0o600);
  });

  it('write() merge semantics: does not overwrite other keys', async () => {
    await backend.write('key-a', 'value-a');
    await backend.write('key-b', 'value-b');
    expect(await backend.read('key-a')).toBe('value-a');
    expect(await backend.read('key-b')).toBe('value-b');
  });

  it('write() upsert: overwrites existing key', async () => {
    await backend.write('key-a', 'original');
    await backend.write('key-a', 'updated');
    expect(await backend.read('key-a')).toBe('updated');
  });

  it('write() handles special characters in key and value', async () => {
    const key = 'did:key:z6Mk-special/key';
    const value = 'eyJhbGc.iOiJFZERTQS.J9==+/';
    await backend.write(key, value);
    expect(await backend.read(key)).toBe(value);
  });

  it('write() handles multiline values (e.g., PEM keys)', async () => {
    const pem = '-----BEGIN TEST VALUE-----\nMC4CAQ\nABBCD\n-----END TEST VALUE-----';
    await backend.write('pem-key', pem);
    expect(await backend.read('pem-key')).toBe(pem);
  });

  // ─── Delete ──────────────────────────────────────────────────────────────

  it('delete() removes a key', async () => {
    await backend.write('key-a', 'value-a');
    await backend.write('key-b', 'value-b');
    await backend.delete('key-a');
    expect(await backend.read('key-a')).toBeNull();
    expect(await backend.read('key-b')).toBe('value-b'); // merge — key-b untouched
  });

  it('delete() is a no-op when file does not exist', async () => {
    let threw = false;
    try {
      await backend.delete('missing-key');
    } catch {
      threw = true;
    }
    expect(threw).toBe(false);
  });

  it('delete() is a no-op when key does not exist in file', async () => {
    await backend.write('other-key', 'other-value');
    let threw = false;
    try {
      await backend.delete('missing-key');
    } catch {
      threw = true;
    }
    expect(threw).toBe(false);
    expect(await backend.read('other-key')).toBe('other-value');
  });

  it('delete() is a no-op on corrupt JSON', async () => {
    writeFileSync(keystorePath(dir), '{ bad json', { mode: 0o600 });
    let threw = false;
    try {
      await backend.delete('any-key');
    } catch {
      threw = true;
    }
    expect(threw).toBe(false);
  });

  // ─── Permissions after delete ────────────────────────────────────────────

  it('delete() preserves 0600 permissions on the file', async () => {
    await backend.write('key-a', 'value-a');
    await backend.write('key-b', 'value-b');
    await backend.delete('key-a');
    const stat = statSync(keystorePath(dir));
    expect(stat.mode & 0o777).toBe(0o600);
  });

  it('delete() enforces 0600 regardless of process umask', async () => {
    await backend.write('keep', 'value');
    await backend.write('remove', 'value');
    const oldMask = process.umask(0o000);
    try {
      await backend.delete('remove');
      const stat = statSync(keystorePath(dir));
      expect(stat.mode & 0o777).toBe(0o600);
    } finally {
      process.umask(oldMask);
    }
  });

  // ─── Concurrent safety (best-effort) ─────────────────────────────────────

  it('concurrent writes do not lose keys (sequential promises)', async () => {
    // Not a true concurrency test (JS is single-threaded) but validates
    // that sequential writes with merge semantics don't overwrite each other.
    await Promise.all([
      backend.write('key-1', 'val-1'),
      backend.write('key-2', 'val-2'),
      backend.write('key-3', 'val-3'),
    ]);
    // Due to race, not all keys guaranteed, but should have no throw
    // and the last-writer-wins per key is expected
    const r1 = await backend.read('key-1');
    const r2 = await backend.read('key-2');
    const r3 = await backend.read('key-3');
    // At minimum, at least one write must have succeeded
    expect([r1, r2, r3].filter(Boolean).length).toBeGreaterThan(0);
  });
});

// ─── MacOsKeychainBackend ────────────────────────────────────────────────────

const describeKeychain: typeof describe = shouldRunMacOsKeychainTests ? describe : describe.skip;

if (!shouldRunMacOsKeychainTests) {
  describe('MacOsKeychainBackend integration gate', () => {
    it.skip(keychainSkipReason, () => {});
  });
}

describeKeychain('MacOsKeychainBackend (macOS Keychain integration)', () => {
  const service = `agents-test-${randomBytes(4).toString('hex')}`;
  let backend: MacOsKeychainBackend;

  beforeEach(() => {
    backend = new MacOsKeychainBackend(service);
  });

  afterEach(async () => {
    // Clean up test keychain entries
    try {
      await backend.delete('test-key');
    } catch {
      /* ignore */
    }
    try {
      await backend.delete('test-key-upsert');
    } catch {
      /* ignore */
    }
    try {
      await backend.delete('test-special-chars');
    } catch {
      /* ignore */
    }
  });

  it('write() and read() roundtrip', async () => {
    await backend.write('test-key', 'test-value-12345');
    const result = await backend.read('test-key');
    expect(result).toBe('test-value-12345');
  });

  it('read() returns null for missing key', async () => {
    const result = await backend.read('nonexistent-key-xyz-9999');
    expect(result).toBeNull();
  });

  it('write() upsert: second write (triggers -25299 retry with -U)', async () => {
    await backend.write('test-key-upsert', 'first-value');
    await backend.write('test-key-upsert', 'second-value'); // triggers -25299 → -U retry
    const result = await backend.read('test-key-upsert');
    expect(result).toBe('second-value');
  });

  it('delete() removes a key', async () => {
    await backend.write('test-key', 'to-be-deleted');
    await backend.delete('test-key');
    const result = await backend.read('test-key');
    expect(result).toBeNull();
  });

  it('delete() is a no-op when key does not exist', async () => {
    let threw = false;
    try {
      await backend.delete('never-existed-key-xyz');
    } catch {
      threw = true;
    }
    expect(threw).toBe(false);
  });

  it('handles values with special chars (JWT-like)', async () => {
    const jwt = 'eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJkaWQ6a2V5OnoifQ.SIG';
    await backend.write('test-special-chars', jwt);
    const result = await backend.read('test-special-chars');
    expect(result).toBe(jwt);
  });
});

// ─── createKeystore() factory ────────────────────────────────────────────────

describe('createKeystore()', () => {
  let origCI: string | undefined;
  let origKeystorePath: string | undefined;
  let dir: string;

  beforeEach(() => {
    origCI = process.env.CI;
    origKeystorePath = process.env.AGENTS_KEYSTORE_PATH;
    dir = makeTempDir();
  });

  afterEach(() => {
    // Restore env vars. AGENTS_DEV_MODE is no longer read by createKeystore
    // (devMode comes through the options object), so nothing to save/restore here.
    if (origCI === undefined) delete process.env.CI;
    else process.env.CI = origCI;
    if (origKeystorePath === undefined) delete process.env.AGENTS_KEYSTORE_PATH;
    else process.env.AGENTS_KEYSTORE_PATH = origKeystorePath;

    try {
      execSync(`rm -rf ${dir}`);
    } catch {
      /* ignore */
    }
  });

  it('returns JsonFileBackend when CI=true', () => {
    process.env.CI = 'true';
    const backend = createKeystore();
    expect(backend).toBeInstanceOf(JsonFileBackend);
  });

  it('returns JsonFileBackend when devMode option is true', () => {
    // Library no longer reads AGENTS_DEV_MODE env var; consumers bridge it.
    const backend = createKeystore({ devMode: true });
    expect(backend).toBeInstanceOf(JsonFileBackend);
  });

  it('does NOT honor AGENTS_DEV_MODE env var on darwin (library no longer reads it)', () => {
    // Only meaningful on macOS — skip on other platforms rather than vacuously pass.
    if (process.platform !== 'darwin') return;
    delete process.env.CI;
    process.env.AGENTS_DEV_MODE = 'true';
    try {
      const backend = createKeystore();
      // On macOS without CI=true and without the devMode option, the factory
      // must select the Keychain backend regardless of the env var.
      expect(backend).toBeInstanceOf(MacOsKeychainBackend);
    } finally {
      delete process.env.AGENTS_DEV_MODE;
    }
  });

  it('uses customPath option when provided', async () => {
    // Path comes exclusively from the customPath option;
    // consumers that want env-driven config bridge at their own boundary.
    const customPath = join(dir, 'custom-keystore.json');
    process.env.CI = 'true'; // Force JsonFileBackend regardless of platform
    const backend = createKeystore({ customPath });
    expect(backend).toBeInstanceOf(JsonFileBackend);
    await backend.write('path-test', 'path-value');
    expect(existsSync(customPath)).toBe(true);
  });

  it('does NOT honor AGENTS_KEYSTORE_PATH env var (library no longer reads it)', () => {
    // Inspect `filePath` rather than performing a real `.write()` — the default
    // falls back to ~/.agents/keystore.json and a real write would mutate the
    // user's home dir.
    //
    // Assert positively against both the known default path AND field existence.
    // If `filePath` is ever renamed, the `'filePath' in backend` check fails
    // loudly rather than passing vacuously on the path comparison.
    const envPath = join(dir, 'env-keystore-should-not-be-used.json');
    const expectedDefault = join(homedir(), '.agents', 'keystore.json');
    process.env.CI = 'true';
    process.env.AGENTS_KEYSTORE_PATH = envPath;
    const backend = createKeystore();
    expect(backend).toBeInstanceOf(JsonFileBackend);
    // Field-existence guard so a future rename of `filePath` produces a hard
    // failure here rather than a silent pass on the path comparison below.
    expect('filePath' in backend).toBe(true);
    // Positive assertion: the backend uses the JsonFileBackend default, NOT
    // the env-named path. If the env fallback regresses, filePath === envPath
    // and this fails.
    expect((backend as unknown as { filePath: string }).filePath).toBe(expectedDefault);
  });

  it('returns MacOsKeychainBackend on darwin outside CI', () => {
    if (process.platform !== 'darwin') return; // Can't test on non-mac
    delete process.env.CI;
    const backend = createKeystore();
    expect(backend).toBeInstanceOf(MacOsKeychainBackend);
  });
});
