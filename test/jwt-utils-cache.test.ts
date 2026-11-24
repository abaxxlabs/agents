import { describe, it, expect, beforeEach } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519';
import { clearJwtKeyCachesForTest, createJwt, verifyJwtSignature } from '../src/crypto/jwt.js';

describe('jwt-utils key cache', () => {
  beforeEach(() => {
    clearJwtKeyCachesForTest();
  });

  it('rejects cross-key verification: jwt signed by A fails against pubKey B', async () => {
    const keyA = ed25519.utils.randomPrivateKey();
    const pubA = ed25519.getPublicKey(keyA);
    const keyB = ed25519.utils.randomPrivateKey();
    const pubB = ed25519.getPublicKey(keyB);

    const jwtFromA = await createJwt({ iss: 'a' }, keyA);
    const jwtFromB = await createJwt({ iss: 'b' }, keyB);

    expect(await verifyJwtSignature(jwtFromA, pubA)).toBe(true);
    expect(await verifyJwtSignature(jwtFromB, pubB)).toBe(true);

    expect(await verifyJwtSignature(jwtFromA, pubB)).toBe(false);
    expect(await verifyJwtSignature(jwtFromB, pubA)).toBe(false);
  });

  it('rejects tampered signature even when cached key is reused', async () => {
    const privateKey = ed25519.utils.randomPrivateKey();
    const publicKey = ed25519.getPublicKey(privateKey);

    const jwt = await createJwt({ iss: 'genuine' }, privateKey);
    expect(await verifyJwtSignature(jwt, publicKey)).toBe(true);

    const [h, p, s] = jwt.split('.');
    const flipped = s.slice(0, -2) + (s.endsWith('AA') ? 'BB' : 'AA');
    const tampered = `${h}.${p}.${flipped}`;
    expect(await verifyJwtSignature(tampered, publicKey)).toBe(false);
  });
});
