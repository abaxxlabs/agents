import type { IDCrypto } from '../types/iddwn-crypto.js';
export declare abstract class CryptoAlgorithm {
    /**
     * Name of the algorithm
     */
    abstract readonly name: string;
    /**
     * Indicates which cryptographic operations are permissible to be used with this algorithm.
     */
    abstract readonly keyUsages: IDCrypto.KeyUsage[] | IDCrypto.KeyPairUsage;
    checkAlgorithmName(options: {
        algorithmName: string;
    }): void;
    checkCryptoKey(options: {
        key: IDCrypto.CryptoKey;
    }): void;
    checkKeyAlgorithm(options: {
        keyAlgorithmName: string;
    }): void;
    checkKeyType(options: {
        keyType: IDCrypto.KeyType;
        allowedKeyType: IDCrypto.KeyType;
    }): void;
    checkKeyUsages(options: {
        keyUsages: IDCrypto.KeyUsage[];
        allowedKeyUsages: IDCrypto.KeyUsage[] | IDCrypto.KeyPairUsage;
    }): void;
    /**
     * Creates an instance of the class on which it is called.
     *
     * This is a generic factory method that creates an instance of any
     * crypto algorithm that extends this abstract class.
     *
     * @template T The type of the instance to be created.
     * @returns An instance of the class it is called on.
     * @throws {TypeError} If the class it is called on cannot be constructed.
     */
    static create<T extends CryptoAlgorithm>(this: new () => T): T;
    abstract decrypt(options: {
        algorithm: IDCrypto.AlgorithmIdentifier | IDCrypto.AesCtrOptions | IDCrypto.AesGcmOptions;
        key: IDCrypto.CryptoKey;
        data: Uint8Array;
    }): Promise<Uint8Array>;
    abstract deriveBits(options: {
        algorithm: IDCrypto.AlgorithmIdentifier | IDCrypto.EcdhDeriveKeyOptions;
        baseKey: IDCrypto.CryptoKey;
        length: number | null;
    }): Promise<Uint8Array>;
    abstract encrypt(options: {
        algorithm: IDCrypto.AlgorithmIdentifier | IDCrypto.AesCtrOptions | IDCrypto.AesGcmOptions;
        key: IDCrypto.CryptoKey;
        data: Uint8Array;
    }): Promise<Uint8Array>;
    abstract generateKey(options: {
        algorithm: Partial<IDCrypto.GenerateKeyOptions>;
        extractable: boolean;
        keyUsages: IDCrypto.KeyUsage[];
    }): Promise<IDCrypto.CryptoKey | IDCrypto.CryptoKeyPair>;
    abstract sign(options: {
        algorithm: IDCrypto.AlgorithmIdentifier | IDCrypto.EcdsaOptions | IDCrypto.EdDsaOptions;
        key: IDCrypto.CryptoKey;
        data: Uint8Array;
    }): Promise<Uint8Array>;
    abstract verify(options: {
        algorithm: IDCrypto.AlgorithmIdentifier | IDCrypto.EcdsaOptions | IDCrypto.EdDsaOptions;
        key: IDCrypto.CryptoKey;
        signature: Uint8Array;
        data: Uint8Array;
    }): Promise<boolean>;
}
//# sourceMappingURL=crypto-algorithm.d.ts.map