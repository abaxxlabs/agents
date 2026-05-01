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

// Unit tests for column encryption: encrypt/decrypt, key management, loadColumnKeys.

import { describe, it, expect, vi } from 'vitest';
import type { Pool } from 'pg';
import {
  encrypt,
  decrypt,
  generateColumnKey,
  wrapColumnKey,
  unwrapColumnKey,
} from '../src/column-encryption.js';
import { loadColumnKeys } from '../src/sql/column-keys.js';
import { asMasterKey } from '../src/crypto/master-key.js';
import { MasterKeyMismatchError } from '../src/errors.js';

describe('Column Encryption Manager', () => {
  const key = generateColumnKey();

  describe('encrypt/decrypt round-trip', () => {
    it('encrypts and decrypts text', () => {
      const value = 'Type 2 Diabetes';
      const ciphertext = encrypt(value, key);
      expect(ciphertext).toBeInstanceOf(Buffer);
      expect(ciphertext.length).toBeGreaterThan(30); // header + data
      expect(decrypt(ciphertext, key)).toBe(value);
    });

    it('encrypts and decrypts integers', () => {
      const value = 42;
      const ciphertext = encrypt(value, key);
      expect(decrypt(ciphertext, key)).toBe(42);
    });

    it('encrypts and decrypts floats', () => {
      const value = 3.14;
      const ciphertext = encrypt(value, key);
      expect(decrypt(ciphertext, key)).toBeCloseTo(3.14);
    });

    it('encrypts and decrypts booleans', () => {
      expect(decrypt(encrypt(true, key), key)).toBe(true);
      expect(decrypt(encrypt(false, key), key)).toBe(false);
    });

    it('encrypts and decrypts JSON objects', () => {
      const value = { diagnosis: 'Type 2 Diabetes', severity: 'moderate' };
      const ciphertext = encrypt(value, key);
      expect(decrypt(ciphertext, key)).toEqual(value);
    });

    it('encrypts and decrypts dates', () => {
      const value = new Date('1990-03-15T00:00:00.000Z');
      const ciphertext = encrypt(value, key);
      const result = decrypt(ciphertext, key) as Date;
      expect(result.toISOString()).toBe(value.toISOString());
    });
  });

  describe('NULL handling', () => {
    it('encrypts NULL as sentinel (not SQL NULL)', () => {
      const ciphertext = encrypt(null, key);
      expect(ciphertext).toBeInstanceOf(Buffer);
      expect(ciphertext.length).toBeGreaterThan(0);
    });

    it('decrypts NULL sentinel back to null', () => {
      const ciphertext = encrypt(null, key);
      expect(decrypt(ciphertext, key)).toBeNull();
    });

    it('decrypts undefined as null', () => {
      const ciphertext = encrypt(undefined, key);
      expect(decrypt(ciphertext, key)).toBeNull();
    });
  });

  describe('wrong key detection', () => {
    it('throws on wrong key (not garbled output)', () => {
      const value = 'sensitive data';
      const ciphertext = encrypt(value, key);
      const wrongKey = generateColumnKey();

      expect(() => decrypt(ciphertext, wrongKey)).toThrow('Decryption failed');
    });

    it('throws on truncated ciphertext', () => {
      expect(() => decrypt(Buffer.alloc(10), key)).toThrow('Ciphertext too short');
    });

    it('throws on wrong version byte', () => {
      const ciphertext = encrypt('test', key);
      ciphertext[0] = 0xff; // corrupt version
      expect(() => decrypt(ciphertext, key)).toThrow('Unsupported wire format');
    });
  });

  describe('key management', () => {
    it('generates 32-byte keys', () => {
      const k = generateColumnKey();
      expect(k.length).toBe(32);
    });

    it('generates unique keys', () => {
      const k1 = generateColumnKey();
      const k2 = generateColumnKey();
      expect(k1.equals(k2)).toBe(false);
    });

    it('wraps and unwraps column key with master key', () => {
      const masterKey = asMasterKey(generateColumnKey());
      const columnKey = generateColumnKey();

      const wrapped = wrapColumnKey(columnKey, masterKey);
      expect(wrapped).toBeInstanceOf(Buffer);
      expect(wrapped.length).toBeGreaterThan(columnKey.length);

      const unwrapped = unwrapColumnKey(wrapped, masterKey);
      expect(unwrapped.equals(columnKey)).toBe(true);
    });

    it('unwrap fails with wrong master key', () => {
      const masterKey = asMasterKey(generateColumnKey());
      const wrongMaster = asMasterKey(generateColumnKey());
      const columnKey = generateColumnKey();

      const wrapped = wrapColumnKey(columnKey, masterKey);
      expect(() => unwrapColumnKey(wrapped, wrongMaster)).toThrow();
    });
  });

  describe('determinism', () => {
    it('produces different ciphertext for same plaintext (IV is random)', () => {
      const value = 'same value';
      const ct1 = encrypt(value, key);
      const ct2 = encrypt(value, key);
      expect(ct1.equals(ct2)).toBe(false);
      // But both decrypt to the same value
      expect(decrypt(ct1, key)).toBe(value);
      expect(decrypt(ct2, key)).toBe(value);
    });
  });
});

describe('loadColumnKeys', () => {
  it('loads decryptable keys, warns about mixed-key rows, and excludes failed rows', async () => {
    const correctMaster = asMasterKey(generateColumnKey());
    const wrongMaster = asMasterKey(generateColumnKey());
    const goodColumnKey = generateColumnKey();
    const badColumnKey = generateColumnKey();

    const goodWrapped = wrapColumnKey(goodColumnKey, correctMaster);
    // badColumn was wrapped with a different master key — simulates stale/rotated key
    const badWrapped = wrapColumnKey(badColumnKey, wrongMaster);

    const mockPool = {
      query: vi.fn().mockResolvedValue({
        rows: [
          {
            table_name: 'patients',
            column_name: 'dob',
            encrypted_key: goodWrapped,
            algorithm: 'aes-256-gcm',
          },
          {
            table_name: 'patients',
            column_name: 'ssn',
            encrypted_key: badWrapped,
            algorithm: 'aes-256-gcm',
          },
        ],
      }),
    } as unknown as Pool;

    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    const result = await loadColumnKeys(mockPool, correctMaster);

    expect(result.has('patients.dob')).toBe(true);
    expect(result.get('patients.dob')!.equals(goodColumnKey)).toBe(true);
    expect(result.has('patients.ssn')).toBe(false);
    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('wrong master key'));

    warnSpy.mockRestore();
  });

  it('throws MasterKeyMismatchError when every persisted key fails to unwrap', async () => {
    const correctMaster = asMasterKey(generateColumnKey());
    const wrongMaster = asMasterKey(generateColumnKey());
    const wrappedWithWrongMaster = wrapColumnKey(generateColumnKey(), wrongMaster);

    const mockPool = {
      query: vi.fn().mockResolvedValue({
        rows: [
          {
            table_name: 'patients',
            column_name: 'dob',
            encrypted_key: wrappedWithWrongMaster,
            algorithm: 'aes-256-gcm',
          },
        ],
      }),
    } as unknown as Pool;

    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    await expect(loadColumnKeys(mockPool, correctMaster)).rejects.toBeInstanceOf(
      MasterKeyMismatchError,
    );

    warnSpy.mockRestore();
  });

  it('returns an empty Map when the table has no rows', async () => {
    const masterKey = asMasterKey(generateColumnKey());
    const mockPool = {
      query: vi.fn().mockResolvedValue({ rows: [] }),
    } as unknown as Pool;

    const result = await loadColumnKeys(mockPool, masterKey);
    expect(result.size).toBe(0);
  });

  it('loads all keys successfully when all are wrapped with the correct master key', async () => {
    const masterKey = asMasterKey(generateColumnKey());
    const key1 = generateColumnKey();
    const key2 = generateColumnKey();

    const mockPool = {
      query: vi.fn().mockResolvedValue({
        rows: [
          {
            table_name: 'orders',
            column_name: 'amount',
            encrypted_key: wrapColumnKey(key1, masterKey),
            algorithm: 'aes-256-gcm',
          },
          {
            table_name: 'orders',
            column_name: 'counterparty',
            encrypted_key: wrapColumnKey(key2, masterKey),
            algorithm: 'aes-256-gcm',
          },
        ],
      }),
    } as unknown as Pool;

    const result = await loadColumnKeys(mockPool, masterKey);
    expect(result.size).toBe(2);
    expect(result.get('orders.amount')!.equals(key1)).toBe(true);
    expect(result.get('orders.counterparty')!.equals(key2)).toBe(true);
  });
});
