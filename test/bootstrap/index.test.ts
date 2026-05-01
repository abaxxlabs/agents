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

// Tests for resolveMasterKeyFromEnv() and resolveTrustedServersFromEnv().
// Each test saves and restores process.env.AGENTS_MASTER_KEY to prevent state leak.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  resolveMasterKeyFromEnv,
  resolveTrustedServersFromEnv,
} from '../../src/bootstrap/index.js';
import { MasterKeyMissingError } from '../../src/errors.js';

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

    it('throws MasterKeyMissingError when AGENTS_MASTER_KEY is empty string', () => {
      process.env.AGENTS_MASTER_KEY = '';
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

    it('accepts uppercase hex', () => {
      process.env.AGENTS_MASTER_KEY = 'AB'.repeat(32);
      expect(() => resolveMasterKeyFromEnv()).not.toThrow();
    });

    it('accepts mixed-case hex', () => {
      process.env.AGENTS_MASTER_KEY = 'aB'.repeat(32);
      expect(() => resolveMasterKeyFromEnv()).not.toThrow();
    });
  });

  describe('rejection paths — strict format check', () => {
    it('throws on 63-character hex (one short)', () => {
      process.env.AGENTS_MASTER_KEY = 'a'.repeat(63);
      expect(() => resolveMasterKeyFromEnv()).toThrow(/64 hex characters/);
      expect(() => resolveMasterKeyFromEnv()).toThrow(/Got 63/);
    });

    it('throws on 65-character hex (one over)', () => {
      process.env.AGENTS_MASTER_KEY = 'a'.repeat(65);
      expect(() => resolveMasterKeyFromEnv()).toThrow(/64 hex characters/);
    });

    it('throws on 64-character string with non-hex character (z)', () => {
      process.env.AGENTS_MASTER_KEY = 'z' + 'a'.repeat(63);
      expect(() => resolveMasterKeyFromEnv()).toThrow(/64 hex characters/);
    });

    it('throws on 64-character string with leading whitespace', () => {
      process.env.AGENTS_MASTER_KEY = ' ' + 'a'.repeat(63);
      expect(() => resolveMasterKeyFromEnv()).toThrow(/64 hex characters/);
    });

    it('throws on 64-character string with trailing newline', () => {
      process.env.AGENTS_MASTER_KEY = 'a'.repeat(63) + '\n';
      expect(() => resolveMasterKeyFromEnv()).toThrow(/64 hex characters/);
    });

    it('throws on base64-style input of correct length', () => {
      process.env.AGENTS_MASTER_KEY = 'A'.repeat(62) + '+/';
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

  it('returns empty array when env var is unset', () => {
    expect(resolveTrustedServersFromEnv()).toEqual([]);
  });

  it('returns empty array when env var is empty string', () => {
    process.env.AGENTS_TRUSTED_SERVERS = '';
    expect(resolveTrustedServersFromEnv()).toEqual([]);
  });

  it('returns empty array when env var is comma-only / whitespace-only', () => {
    process.env.AGENTS_TRUSTED_SERVERS = ',,,   ,, ';
    expect(resolveTrustedServersFromEnv()).toEqual([]);
  });

  it('parses a single DID', () => {
    process.env.AGENTS_TRUSTED_SERVERS = 'did:key:z6Mka';
    expect(resolveTrustedServersFromEnv()).toEqual(['did:key:z6Mka']);
  });

  it('parses comma-separated DIDs', () => {
    process.env.AGENTS_TRUSTED_SERVERS = 'did:key:z6Mka,did:key:z6Mkb,did:key:z6Mkc';
    expect(resolveTrustedServersFromEnv()).toEqual([
      'did:key:z6Mka',
      'did:key:z6Mkb',
      'did:key:z6Mkc',
    ]);
  });

  it('trims whitespace around each entry', () => {
    process.env.AGENTS_TRUSTED_SERVERS = '  did:key:z6Mka  ,\tdid:key:z6Mkb\t';
    expect(resolveTrustedServersFromEnv()).toEqual(['did:key:z6Mka', 'did:key:z6Mkb']);
  });

  it('drops empty entries from trailing comma / consecutive commas', () => {
    process.env.AGENTS_TRUSTED_SERVERS = 'did:key:z6Mka,,did:key:z6Mkb,';
    expect(resolveTrustedServersFromEnv()).toEqual(['did:key:z6Mka', 'did:key:z6Mkb']);
  });

  it('deduplicates entries (first occurrence wins)', () => {
    process.env.AGENTS_TRUSTED_SERVERS = 'did:key:z6Mka,did:key:z6Mkb,did:key:z6Mka';
    expect(resolveTrustedServersFromEnv()).toEqual(['did:key:z6Mka', 'did:key:z6Mkb']);
  });

  it('does not validate DID format (intentional — format-agnostic)', () => {
    // Malformed entries pass through; downstream trust lookups simply never match them.
    process.env.AGENTS_TRUSTED_SERVERS = 'not-a-did,definitely-not-a-did';
    expect(resolveTrustedServersFromEnv()).toEqual(['not-a-did', 'definitely-not-a-did']);
  });
});
