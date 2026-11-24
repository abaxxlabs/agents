import { describe, it, expect } from 'vitest';
import { encrypt, decrypt, generateColumnKey } from '#encryption/index.js';

describe('Column Encryption Manager', () => {
  const key = generateColumnKey();

  it('encrypts and decrypts text', () => {
    const value = 'Type 2 Diabetes';
    const ciphertext = encrypt(value, key);
    expect(ciphertext).toBeInstanceOf(Buffer);
    expect(ciphertext.length).toBeGreaterThan(30);
    expect(decrypt(ciphertext, key)).toBe(value);
  });

  it('throws on wrong key (not garbled output)', () => {
    const value = 'sensitive data';
    const ciphertext = encrypt(value, key);
    const wrongKey = generateColumnKey();

    expect(() => decrypt(ciphertext, wrongKey)).toThrow('Decryption failed');
  });
});
