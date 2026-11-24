import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { statSync, mkdirSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomBytes } from 'node:crypto';
import { JsonFileBackend, MacOsKeychainBackend, createKeystore } from '#identity/keystore.js';
import { keychainSkipReason, shouldRunMacOsKeychainTests } from './support/integration-gates.js';

function makeTempDir(): string {
  const dir = join(tmpdir(), `agents-test-${randomBytes(4).toString('hex')}`);
  mkdirSync(dir, { recursive: true });
  return dir;
}

function keystorePath(dir: string): string {
  return join(dir, 'keystore.json');
}

describe('JsonFileBackend', () => {
  let dir: string;
  let backend: JsonFileBackend;

  beforeEach(() => {
    dir = makeTempDir();
    backend = new JsonFileBackend(keystorePath(dir));
  });

  afterEach(() => {
    try {
      execSync(`rm -rf ${dir}`);
    } catch {
      /* ignore */
    }
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
});

if (!shouldRunMacOsKeychainTests) {
  describe('MacOsKeychainBackend integration gate', () => {
    it.skip(keychainSkipReason, () => {});
  });
} else {
  describe('MacOsKeychainBackend integration', () => {
    it('persists, replaces and deletes a value in the native Keychain', async () => {
      const backend = new MacOsKeychainBackend(`agents-test-${randomBytes(8).toString('hex')}`);
      const key = 'test-key';
      try {
        await backend.write(key, 'first-value');
        expect(await backend.read(key)).toBe('first-value');
        await backend.write(key, 'replacement-value');
        expect(await backend.read(key)).toBe('replacement-value');
        await backend.delete(key);
        expect(await backend.read(key)).toBeNull();
      } finally {
        await backend.delete(key);
      }
    });
  });
}

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
});
