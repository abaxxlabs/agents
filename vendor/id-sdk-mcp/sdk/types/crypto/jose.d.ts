import { MulticodecCode, MulticodecDefinition } from '../common/index.js';
import type { IDCrypto } from './types/iddwn-crypto.js';
import { CryptoKey } from './algorithms-api/index.js';
/**
 * JSON Web Key Operations
 *
 * decrypt    : Decrypt content and validate decryption, if applicable
 * deriveBits : Derive bits not to be used as a key
 * deriveKey  : Derive key
 * encrypt    : Encrypt content
 * sign       : Compute digital signature or MAC
 * unwrapKey  : Decrypt key and validate decryption, if applicable
 * verify     : Verify digital signature or MAC
 * wrapKey    : Encrypt key
 */
export type JwkOperation = IDCrypto.KeyUsage[] | string[];
/**
 * JSON Web Key Use
 *
 * sig : Digital Signature or MAC
 * enc : Encryption
 */
export type JwkUse = 'sig' | 'enc' | string;
/**
 * JSON Web Key Types
 */
export type JwkType = 
/**
 * Elliptic Curve
 * Used with Elliptic Curve Digital Signature Algorithm (ECDSA) and Elliptic
 * Curve Diffie-Hellman (ECDH), including secp256k1, P-256, P-384, and P-521.
 */
'EC'
/**
 * RSA
 * Widely used for encryption and digital signatures. RSA keys are used in
 * various algorithms like RS256, RS384, RS512, etc.
 */
 | 'RSA'
/**
 * Octet sequence
 * Used with symmetric signing (e.g., HMAC HS256, HS512, etc.) and
 * symmetric encryption (e.g., A256CBC-HS512, A256GCM, etc.) algorithms.
 */
 | 'oct'
/**
 * Octet string key pairs (OKP)
 * A type of public key that is used with algorithms such as EdDSA (Ed25519 and
 * Ed448 curves) and ECDH (X25519 and X448 curves).
 */
 | 'OKP';
/**
 * JSON Web Key Elliptic Curve
 */
export type JwkNamedCurves = 'P-256' | 'P-384' | 'P-521' | 'Ed25519' | 'Ed448' | 'X25519' | 'X448' | 'secp256k1';
/**
 * JSON Web Key Parameters
 */
export type JwkParamsAnyKeyType = {
    alg?: string;
    ext?: 'true' | 'false';
    key_ops?: JwkOperation;
    kid?: string;
    kty: JwkType;
    use?: JwkUse;
    x5c?: string;
    x5t?: string;
    'x5t#S256'?: string;
    x5u?: string;
};
export type JwkParamsEcPublic = Omit<JwkParamsAnyKeyType, 'alg' | 'kty'> & {
    /**
     * The algorithm intended for use with the key.
     * ES256  : ECDSA using P-256 and SHA-256
     * ES256K : ECDSA using secp256k1 curve and SHA-256
     * ES384  : ECDSA using P-384 and SHA-384
     * ES512  : ECDSA using P-521 and SHA-512
     */
    alg?: 'ES256' | 'ES256K' | 'ES384' | 'ES512';
    /**
     * Elliptic Curve key pair.
     */
    kty: 'EC';
    /**
     * The cryptographic curve used with the key.
     * MUST be present for all EC public keys.
     */
    crv: 'secp256k1' | 'P-256' | 'P-384' | 'P-521';
    /**
     * The x-coordinate for the Elliptic Curve point.
     * Represented as the base64url encoding of the octet string
     * representation of the coordinate.
     * MUST be present for all EC public keys
     */
    x: string;
    /**
     * The y-coordinate for the Elliptic Curve point.
     * Represented as the base64url encoding of the octet string
     * representation of the coordinate.
     * MUST be present only for secp256k1 public keys.
     */
    y?: string;
};
export type JwkParamsEcPrivate = JwkParamsEcPublic & {
    /**
     * The d-coordinate for the Elliptic Curve point.
     * Represented as the base64url encoding of the octet string
     * representation of the coordinate.
     * MUST be present for all EC private keys.
     */
    d: string;
};
export type JwkParamsOkpPublic = Omit<JwkParamsAnyKeyType, 'kty' | 'alg' | 'crv'> & Pick<JwkParamsEcPublic, 'x'> & {
    /**
     * The algorithm intended for use with the key.
     * EdDSA: Edwards Curve Digital Signature Algorithm
     */
    alg?: 'EdDSA';
    /**
     * The cryptographic curve used with the key.
     * MUST be present for all OKP public keys.
     */
    crv: 'Ed25519' | 'Ed448' | 'X25519' | 'X448';
    /**
     * Key type
     * OKP (Octet Key Pair) is defined for public key algorithms that use octet
     * strings as private and public keys.
     */
    kty: 'OKP';
};
export type JwkParamsOkpPrivate = JwkParamsOkpPublic & {
    /**
     * The d-coordinate for the Edwards Curve point.
     * Represented as the base64url encoding of the octet string
     * representation of the coordinate.
     * MUST be present for all EC private keys.
     */
    d: string;
};
export type JwkParamsOctPrivate = Omit<JwkParamsAnyKeyType, 'alg' | 'kty'> & {
    /**
     * The algorithm intended for use with the key.
     * Used with symmetric signing (e.g., HMAC HS256, etc.) and
     * symmetric encryption (e.g., A256GCM, etc.) algorithms.
     */
    alg?: 'A128CBC' | 'A192CBC' | 'A256CBC' | 'A128CTR' | 'A192CTR' | 'A256CTR' | 'A128GCM' | 'A192GCM' | 'A256GCM' | 'HS256' | 'HS384' | 'HS512';
    /**
     * The "k" (key value) parameter contains the value of the symmetric
     * (or other single-valued) key.  It is represented as the base64url
     * encoding of the octet sequence containing the key value.
     */
    k: string;
    /**
     * Key type
     * oct (Octet Sequence) is defined for symmetric encryption and
     * symmetric signature algorithms.
     */
    kty: 'oct';
};
export type JwkParamsRsaPublic = Omit<JwkParamsAnyKeyType, 'kty'> & {
    e: string;
    /**
     * Key type
     * RSA is widely used for encryption and digital signatures.
     */
    kty: 'RSA';
    n: string;
};
export type JwkParamsRsaPrivate = JwkParamsRsaPublic & {
    d: string;
    p?: string;
    q?: string;
    dp?: string;
    dq?: string;
    qi?: string;
    oth?: {
        r: string;
        d: string;
        t: string;
    }[];
};
export type PublicKeyJwk = JwkParamsEcPublic | JwkParamsOkpPublic | JwkParamsRsaPublic;
export type PrivateKeyJwk = JwkParamsEcPrivate | JwkParamsOkpPrivate | JwkParamsOctPrivate | JwkParamsRsaPrivate;
export type JwkKeyPair = {
    publicKeyJwk: PublicKeyJwk;
    privateKeyJwk: PrivateKeyJwk;
};
export type JsonWebKey = PrivateKeyJwk | PublicKeyJwk;
export interface JoseHeaderParams {
    cty?: string;
    jku?: string;
    jwk?: PublicKeyJwk;
    kid?: string;
    typ?: string;
    x5c?: string[];
    x5t?: string;
    x5u?: string;
}
export interface JwsHeaderParams extends JoseHeaderParams {
    alg: 'EdDSA' | 'ES256' | 'ES256K' | 'ES384' | 'ES512' | 'HS256' | 'HS384' | 'HS512';
    crit?: string[];
    [key: string]: unknown;
}
export interface JweHeaderParams extends JoseHeaderParams {
    alg: 'A128KW' | 'A192KW' | 'A256KW' | 'dir' | 'ECDH-ES' | 'ECDH-ES+A128KW' | 'ECDH-ES+A192KW' | 'ECDH-ES+A256KW' | 'A128GCMKW' | 'A192GCMKW' | 'A256GCMKW' | 'PBES2-HS256+A128KW' | 'PBES2-HS384+A192KW' | 'PBES2-HS512+A256KW' | 'PBES2-HS512+XC20PKW';
    apu?: Uint8Array;
    apv?: Uint8Array;
    crit?: string[];
    /**
     * Cryptographic Algorithms for Content Encryption
     * JWE uses cryptographic algorithms to encrypt and integrity-protect the
     * plaintext and to integrity-protect the Additional Authenticated Data.
     */
    enc: 'A128CBC-HS256' | 'A192CBC-HS384' | 'A256CBC-HS512' | 'A128GCM' | 'A192GCM' | 'A256GCM' | 'XC20P';
    epk?: Uint8Array;
    iv?: Uint8Array;
    p2c?: number;
    p2s?: string;
    [key: string]: unknown;
}
export declare class Jose {
    static cryptoKeyToJwk(options: {
        key: IDCrypto.CryptoKey;
    }): Promise<JsonWebKey>;
    static cryptoKeyToJwkPair(options: {
        keyPair: IDCrypto.CryptoKeyPair;
    }): Promise<JwkKeyPair>;
    static joseToMulticodec(options: {
        key: JsonWebKey;
    }): Promise<MulticodecDefinition<MulticodecCode>>;
    static joseToWebCrypto(options: Partial<JsonWebKey>): IDCrypto.GenerateKeyOptions;
    /**
     * Computes the thumbprint of a JSON Web Key (JWK) using the method
     * specified in RFC 7638. This function accepts RSA, EC, OKP, and oct keys
     * and returns the thumbprint as a base64url encoded SHA-256 hash of the
     * JWK's required members, serialized and sorted lexicographically.
     *
     * Purpose:
     * - Uniquely Identifying Keys: The thumbprint allows the unique
     *   identification of a specific JWK within a set of JWKs. It provides a
     *   deterministic way to generate a value that can be used as a key
     *   identifier (kid) or to match a specific key.
     *
     * - Simplifying Key Management: In systems where multiple keys are used,
     *   managing and identifying individual keys can become complex. The
     *   thumbprint method simplifies this by creating a standardized, unique
     *   identifier for each key.
     *
     * - Enabling Interoperability: By standardizing the method to compute a
     *   thumbprint, different systems can compute the same thumbprint value for
     *   a given JWK. This enables interoperability among systems that use JWKs.
     *
     * - Secure Comparison: The thumbprint provides a way to securely compare
     *   JWKs to determine if they are equivalent.
     *
     * @param jwk - The JSON Web Key for which the thumbprint will be computed.
     *              This must be an RSA, EC, OKP, or oct key.
     * @returns The thumbprint as a base64url encoded string.
     * @throws {Error} Throws an error if the provided key type is unsupported.
     *
     * @example
     * const jwk: PublicKeyJwk = {
     *   'kty': 'EC',
     *   'crv': 'secp256k1',
     *   'x': '61iPYuGefxotzBdQZtDvv6cWHZmXrTTscY-u7Y2pFZc',
     *   'y': '88nPCVLfrAY9i-wg5ORcwVbHWC_tbeAd1JE2e0co0lU'
     * };
     *
     * const thumbprint = jwkThumbprint(jwk);
     * console.log(`JWK thumbprint: ${thumbprint}`);
     *
     * @see {@link https://datatracker.ietf.org/doc/html/rfc7638 | RFC7638} for
     * the specification of JWK thumbprint computation.
     */
    static jwkThumbprint(options: {
        key: JsonWebKey;
    }): Promise<string>;
    static jwkToCryptoKey(options: {
        key: JsonWebKey;
    }): Promise<IDCrypto.CryptoKey>;
    static jwkToKey(options: {
        key: JsonWebKey;
    }): Promise<{
        keyMaterial: Uint8Array;
        keyType: IDCrypto.KeyType;
    }>;
    /**
    * Note: All secp public keys are converted to compressed point encoding
    *    before the multibase identifier is computed.
    *
    * Per {@link https://github.com/multiformats/multicodec/blob/master/table.csv | Multicodec table}:
    *    public keys for Elliptic Curve cryptography algorithms (e.g., secp256k1,
    *    secp256k1r1, secp384r1, etc.) are always represented with compressed point
    *    encoding (e.g., secp256k1-pub, p256-pub, p384-pub, etc.).
    *
    * Per {@link https://datatracker.ietf.org/doc/html/rfc8812#name-jose-and-cose-secp256k1-cur | RFC 8812}:
    *    "As a compressed point encoding representation is not defined for JWK
    *    elliptic curve points, the uncompressed point encoding defined there
    *    MUST be used. The x and y values represented MUST both be exactly
    *    256 bits, with any leading zeros preserved.
    *
    */
    static jwkToMultibaseId(options: {
        key: JsonWebKey;
    }): Promise<string>;
    static keyToJwk(options: Partial<JsonWebKey> & {
        keyMaterial: Uint8Array;
        keyType: IDCrypto.KeyType;
    }): Promise<JsonWebKey>;
    static multicodecToJose(options: {
        code?: MulticodecCode;
        name?: string;
    }): Promise<JsonWebKey>;
    static webCryptoToJose(options: IDCrypto.Algorithm | IDCrypto.GenerateKeyOptions): Partial<JsonWebKey>;
    private static canonicalize;
}
type Constructable = new (...args: any[]) => object;
export declare function CryptoKeyToJwkMixin<T extends Constructable>(Base: T): {
    new (...args: any[]): {
        toJwk(): Promise<JsonWebKey>;
    };
} & T;
export declare const CryptoKeyWithJwk: {
    new (...args: any[]): {
        toJwk(): Promise<JsonWebKey>;
    };
} & typeof CryptoKey;
export {};
//# sourceMappingURL=jose.d.ts.map