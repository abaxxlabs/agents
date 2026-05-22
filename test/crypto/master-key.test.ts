import { describe, it, expect } from 'vitest';
import { asMasterKey } from '../../src/crypto/master-key.js';

describe('asMasterKey', () => {
  describe('positive paths', () => {
    it('accepts exactly 32 bytes and returns the same Buffer reference', () => {
      const buf = Buffer.alloc(32, 0xab);
      const mk = asMasterKey(buf);
      expect(mk).toBe(buf);
      expect(mk).toBeInstanceOf(Buffer);
      expect(mk.length).toBe(32);
    });

    it('accepts a 32-byte buffer of any byte content', () => {
      const zero = Buffer.alloc(32, 0x00);
      expect(() => asMasterKey(zero)).not.toThrow();
    });
  });

  describe('negative paths — wrong length throws', () => {
    it('throws on 31-byte buffer (one short)', () => {
      expect(() => asMasterKey(Buffer.alloc(31))).toThrow(/32 bytes/);
      expect(() => asMasterKey(Buffer.alloc(31))).toThrow(/got 31/);
    });

    it('throws on 33-byte buffer (one over)', () => {
      expect(() => asMasterKey(Buffer.alloc(33))).toThrow(/32 bytes/);
      expect(() => asMasterKey(Buffer.alloc(33))).toThrow(/got 33/);
    });

    it('throws on empty buffer (the format-sniff failure mode)', () => {
      // Buffer.from('non-hex', 'hex') silently returns 0 bytes; this catches that.
      expect(() => asMasterKey(Buffer.alloc(0))).toThrow(/32 bytes/);
      expect(() => asMasterKey(Buffer.alloc(0))).toThrow(/got 0/);
    });

    it('throws on 16-byte buffer (AES-128 key size, plausible mistake)', () => {
      expect(() => asMasterKey(Buffer.alloc(16))).toThrow(/32 bytes/);
    });

    it('throws on 64-byte buffer (someone forgot to hex-decode)', () => {
      expect(() => asMasterKey(Buffer.alloc(64))).toThrow(/32 bytes/);
    });
  });
});
