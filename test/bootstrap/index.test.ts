import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { resolveMasterKeyFromEnv, resolveTrustedServersFromEnv } from '#bootstrap/index.js';
import { MasterKeyMissingError } from '#errors/index.js';

let savedEnv: string | undefined;

beforeEach(() => {
  savedEnv = process.env.AGENTS_MASTER_KEY;
  delete process.env.AGENTS_MASTER_KEY;
});

afterEach(() => {
  if (savedEnv !== undefined) {
    process.env.AGENTS_MASTER_KEY = savedEnv;
  } else {
    delete process.env.AGENTS_MASTER_KEY;
  }
});

describe('resolveMasterKeyFromEnv', () => {
  describe('missing or empty env var', () => {
    it('throws MasterKeyMissingError when AGENTS_MASTER_KEY is unset', () => {
      expect(() => resolveMasterKeyFromEnv()).toThrow(MasterKeyMissingError);
    });
  });

  describe('valid 64-char hex inputs', () => {
    it('accepts lowercase hex and returns a 32-byte Buffer', () => {
      process.env.AGENTS_MASTER_KEY = 'ab'.repeat(32);
      const mk = resolveMasterKeyFromEnv();
      expect(mk).toBeInstanceOf(Buffer);
      expect(mk.length).toBe(32);
      expect(mk[0]).toBe(0xab);
      expect(mk[31]).toBe(0xab);
    });
  });

  describe('rejection paths — strict format check', () => {
    it('throws on 63-character hex (one short)', () => {
      process.env.AGENTS_MASTER_KEY = 'a'.repeat(63);
      expect(() => resolveMasterKeyFromEnv()).toThrow(/64 hex characters/);
      expect(() => resolveMasterKeyFromEnv()).toThrow(/Got 63/);
    });

    it('throws on 64-character string with non-hex character (z)', () => {
      process.env.AGENTS_MASTER_KEY = 'z' + 'a'.repeat(63);
      expect(() => resolveMasterKeyFromEnv()).toThrow(/64 hex characters/);
    });

    it('error message does NOT echo the env-var value (no leakage)', () => {
      const sensitive = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbe';
      process.env.AGENTS_MASTER_KEY = sensitive;
      try {
        resolveMasterKeyFromEnv();
        throw new Error('expected throw');
      } catch (err) {
        const message = (err as Error).message;
        expect(message).not.toContain(sensitive);
      }
    });
  });
});

describe('resolveTrustedServersFromEnv', () => {
  let savedTrusted: string | undefined;

  beforeEach(() => {
    savedTrusted = process.env.AGENTS_TRUSTED_SERVERS;
    delete process.env.AGENTS_TRUSTED_SERVERS;
  });

  afterEach(() => {
    if (savedTrusted !== undefined) process.env.AGENTS_TRUSTED_SERVERS = savedTrusted;
    else delete process.env.AGENTS_TRUSTED_SERVERS;
  });

  it('parses comma-separated DIDs', () => {
    process.env.AGENTS_TRUSTED_SERVERS = 'did:key:z6Mka,did:key:z6Mkb,did:key:z6Mkc';
    expect(resolveTrustedServersFromEnv()).toEqual([
      'did:key:z6Mka',
      'did:key:z6Mkb',
      'did:key:z6Mkc',
    ]);
  });

  it('deduplicates entries (first occurrence wins)', () => {
    process.env.AGENTS_TRUSTED_SERVERS = 'did:key:z6Mka,did:key:z6Mkb,did:key:z6Mka';
    expect(resolveTrustedServersFromEnv()).toEqual(['did:key:z6Mka', 'did:key:z6Mkb']);
  });
});
