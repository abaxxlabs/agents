import { describe, it, expect } from 'vitest';
import { randomBytes } from 'node:crypto';
import { zbase32Decode, zbase32Encode } from '#crypto/zbase32.js';

describe('z-base-32', () => {
  it('round-trips arbitrary byte sequences', () => {
    for (const len of [1, 2, 5, 20, 32, 33, 64]) {
      const bytes = new Uint8Array(randomBytes(len));
      expect(Buffer.from(zbase32Decode(zbase32Encode(bytes))).equals(Buffer.from(bytes))).toBe(
        true,
      );
    }
  });

  it('encodes a 32-byte key as 52 characters', () => {
    expect(zbase32Encode(new Uint8Array(randomBytes(32))).length).toBe(52);
  });

  it('pads the final character with zeroes, which is what makes the round-trip canonical', () => {
    // 32 bytes leave four spare bits in the 52nd character, so a canonical encoder
    // only ever emits the two alphabet entries whose low four bits are zero.
    const finals = new Set<string>();
    for (let i = 0; i < 100; i++) finals.add(zbase32Encode(new Uint8Array(randomBytes(32)))[51]);
    expect([...finals].sort()).toEqual(['o', 'y']);
  });

  it('rejects a character outside the alphabet', () => {
    expect(() => zbase32Decode('yv')).toThrow(/Invalid z-base-32 character/);
  });
});
