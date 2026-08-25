import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519';
import { importJWK } from 'jose';
import {
  clearJwtKeyCachesForTest,
  createJwt,
  setJwtImportJwkForTest,
  verifyJwtSignature,
} from '../src/crypto/jwt.js';

const importJwkSpy = vi.fn();

describe('jwt-utils key cache', () => {
  beforeEach(() => {
    clearJwtKeyCachesForTest();
    importJwkSpy.mockClear();
    setJwtImportJwkForTest(((...args: Parameters<typeof importJWK>) => {
      importJwkSpy(...args);
      return importJWK(...args);
    }) as typeof importJWK);
  });

  afterEach(() => {
    setJwtImportJwkForTest();
  });

  it('signs N JWTs with one importJWK call when reusing the same private key', async () => {
    const privateKey = ed25519.utils.randomPrivateKey();
    for (let i = 0; i < 100; i++) {
      await createJwt({ iss: `agent-${i}` }, privateKey);
    }
    expect(importJwkSpy).toHaveBeenCalledTimes(1);
  });

  it('verifies N credentials from the same issuer with one importJWK call', async () => {
    const privateKey = ed25519.utils.randomPrivateKey();
    const publicKey = ed25519.getPublicKey(privateKey);

    const jwts: string[] = [];
    for (let i = 0; i < 50; i++) {
      jwts.push(await createJwt({ iss: 'same-issuer', jti: `${i}` }, privateKey));
    }
    importJwkSpy.mockClear();

    for (const jwt of jwts) {
      const ok = await verifyJwtSignature(jwt, publicKey);
      expect(ok).toBe(true);
    }
    expect(importJwkSpy).toHaveBeenCalledTimes(1);
  });

  it('imports once per distinct private key', async () => {
    const keyA = ed25519.utils.randomPrivateKey();
    const keyB = ed25519.utils.randomPrivateKey();
    await createJwt({ iss: 'a' }, keyA);
    await createJwt({ iss: 'b' }, keyB);
    await createJwt({ iss: 'a2' }, keyA);
    await createJwt({ iss: 'b2' }, keyB);
    expect(importJwkSpy).toHaveBeenCalledTimes(2);
  });

  it('round-trip: cached signer and verifier produce valid signatures', async () => {
    const privateKey = ed25519.utils.randomPrivateKey();
    const publicKey = ed25519.getPublicKey(privateKey);

    const jwt1 = await createJwt({ iss: 'first' }, privateKey);
    const jwt2 = await createJwt({ iss: 'second' }, privateKey);

    expect(await verifyJwtSignature(jwt1, publicKey)).toBe(true);
    expect(await verifyJwtSignature(jwt2, publicKey)).toBe(true);
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

  it('does not cache public key on failed verification', async () => {
    const privateKey = ed25519.utils.randomPrivateKey();
    const publicKey = ed25519.getPublicKey(privateKey);
    const wrongPublicKey = ed25519.getPublicKey(ed25519.utils.randomPrivateKey());

    const jwt = await createJwt({ iss: 'real' }, privateKey);
    importJwkSpy.mockClear();

    expect(await verifyJwtSignature(jwt, wrongPublicKey)).toBe(false);
    expect(await verifyJwtSignature(jwt, wrongPublicKey)).toBe(false);
    expect(importJwkSpy).toHaveBeenCalledTimes(2);

    importJwkSpy.mockClear();
    expect(await verifyJwtSignature(jwt, publicKey)).toBe(true);
    expect(await verifyJwtSignature(jwt, publicKey)).toBe(true);
    expect(importJwkSpy).toHaveBeenCalledTimes(1);
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
