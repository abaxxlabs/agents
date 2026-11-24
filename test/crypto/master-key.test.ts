import { describe, it, expect } from 'vitest';
import { asMasterKey } from '#crypto/master-key.js';

describe('asMasterKey', () => {
  describe('negative paths — wrong length throws', () => {
    it('throws on 64-byte buffer (someone forgot to hex-decode)', () => {
      expect(() => asMasterKey(Buffer.alloc(64))).toThrow(/32 bytes/);
    });
  });
});
