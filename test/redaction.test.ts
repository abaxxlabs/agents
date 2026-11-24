import { describe, it, expect } from 'vitest';
import { REDACTED_SIGNER } from '#crypto/redact.js';
import { createSigner } from '#auth/did-key.js';
import { generateDidKey } from '#auth/did-key.js';

describe('createSigner redaction', () => {
  const { privateKey } = generateDidKey();
  const signer = createSigner(privateKey);
  const privateKeyHex = Buffer.from(privateKey).toString('hex');

  it('JSON.stringify returns the redaction marker, not key bytes', () => {
    const json = JSON.stringify(signer);
    expect(json).not.toContain(privateKeyHex);
    expect(json).toContain(REDACTED_SIGNER);
  });
});
