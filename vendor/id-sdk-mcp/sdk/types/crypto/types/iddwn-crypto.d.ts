export declare namespace IDCrypto {
    interface AesCtrOptions extends Algorithm {
        counter: Uint8Array;
        length: number;
    }
    interface AesGenerateKeyOptions extends Algorithm {
        length: number;
    }
    interface AesGcmOptions extends Algorithm {
        additionalData?: Uint8Array;
        iv: Uint8Array;
        tagLength?: number;
    }
    interface Algorithm {
        name: string;
    }
    type AlgorithmIdentifier = Algorithm;
    interface CryptoKey {
        algorithm: IDCrypto.Algorithm;
        extractable: boolean;
        material: Uint8Array;
        type: KeyType;
        usages: KeyUsage[];
    }
    interface CryptoKeyPair {
        privateKey: CryptoKey;
        publicKey: CryptoKey;
    }
    interface EcdsaOptions extends Algorithm {
        hash: string;
    }
    interface EcGenerateKeyOptions extends Algorithm {
        namedCurve: NamedCurve;
    }
    interface EcdhDeriveKeyOptions extends Algorithm {
        publicKey: CryptoKey;
    }
    interface EcdsaGenerateKeyOptions extends EcGenerateKeyOptions {
        compressedPublicKey?: boolean;
    }
    type EdDsaGenerateKeyOptions = EcGenerateKeyOptions;
    type EdDsaOptions = Algorithm;
    type GenerateKeyOptions = AesGenerateKeyOptions | EcGenerateKeyOptions | HmacGenerateKeyOptions;
    interface HmacGenerateKeyOptions extends Algorithm {
        hash: AlgorithmIdentifier;
        length?: number;
    }
    interface KeyAlgorithm {
        name: string;
    }
    type KeyFormat = 'jwk' | 'pkcs8' | 'raw' | 'spki';
    interface KeyPairUsage {
        privateKey: KeyUsage[];
        publicKey: KeyUsage[];
    }
    /**
     * KeyType
     *
     * The read-only `type` property indicates which kind of key
     * is represented by the object.
     *
     * It can have the following string values:
     *
     *   "secret": This key is a secret key for use with a symmetric algorithm.
     *   "private": This key is the private half of an asymmetric algorithm's `ManagedKeyPair`.
     *   "public": This key is the public half of an asymmetric algorithm's `ManagedKeyPair`.
     */
    type KeyType = 'private' | 'public' | 'secret';
    /**
     * KeyUsage
     *
     * The read-only usage property indicates what can be done with the key.
     *
     * An Array of strings from the following list:
     *
     *   "encrypt": The key may be used to encrypt messages.
     *   "decrypt": The key may be used to decrypt messages.
     *   "sign": The key may be used to sign messages.
     *   "verify": The key may be used to verify signatures.
     *   "deriveKey": The key may be used in deriving a new key.
     *   "deriveBits": The key may be used in deriving bits.
     *   "wrapKey": The key may be used to wrap a key.
     *   "unwrapKey": The key may be used to unwrap a key.
     *
     * Reference: IANA "JSON Web Key Operations" registry
     *            https://www.iana.org/assignments/jose/jose.xhtml#web-key-operations
     */
    type KeyUsage = 'encrypt' | 'decrypt' | 'sign' | 'verify' | 'deriveKey' | 'deriveBits' | 'wrapKey' | 'unwrapKey';
    type NamedCurve = string;
    interface Pbkdf2Options extends Algorithm {
        hash: string;
        iterations: number;
        salt: Uint8Array;
    }
    type PrivateKeyType = 'private' | 'secret';
}
//# sourceMappingURL=iddwn-crypto.d.ts.map