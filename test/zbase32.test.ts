import { describe, it, expect } from 'vitest';
import { zbase32Decode } from '#crypto/zbase32.js';

describe('z-base-32', () => {
  it('rejects a character outside the alphabet', () => {
    expect(() => zbase32Decode('yv')).toThrow(/Invalid z-base-32 character/);
  });
});
