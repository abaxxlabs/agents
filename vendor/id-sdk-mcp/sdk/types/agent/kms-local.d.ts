import { CryptoAlgorithm } from '../crypto/index.js';
import { ManagedKey, PortableKey, SignOptions, VerifyOptions, DecryptOptions, EncryptOptions, ManagedKeyPair, ManagedKeyStore, GenerateKeyType, PortableKeyPair, UpdateKeyOptions, DeriveBitsOptions, ManagedPrivateKey, GenerateKeyOptions, KeyManagementSystem, GenerateKeyOptionTypes } from './types/managed-key.js';
import { IDManagedAgent } from './types/agent.js';
export type AlgorithmImplementation = typeof CryptoAlgorithm & {
    new (): CryptoAlgorithm;
};
export type AlgorithmImplementations = {
    [algorithmName: string]: AlgorithmImplementation;
};
export type KmsOptions = {
    agent?: IDManagedAgent;
    cryptoAlgorithms?: AlgorithmImplementations;
    keyStore?: ManagedKeyStore<string, ManagedKey | ManagedKeyPair>;
    kmsName: string;
    privateKeyStore?: ManagedKeyStore<string, ManagedPrivateKey>;
};
export declare const defaultAlgorithms: AlgorithmImplementations;
export declare class LocalKms implements KeyManagementSystem {
    /**
     * Holds the instance of a `IDManagedAgent` that represents the current
     * execution context for the `KeyManager`. This agent is utilized
     * to interact with other agent components. It's vital
     * to ensure this instance is set to correctly contextualize
     * operations within the broader agent framework.
     */
    private _agent?;
    private _name;
    private _keyStore;
    private _privateKeyStore;
    private _supportedAlgorithms;
    constructor(options: KmsOptions);
    /**
     * Retrieves the `IDManagedAgent` execution context.
     * If the `agent` instance proprety is undefined, it will throw an error.
     *
     * @returns The `IDManagedAgent` instance that represents the current execution
     * context.
     *
     * @throws Will throw an error if the `agent` instance property is undefined.
     */
    get agent(): IDManagedAgent;
    set agent(agent: IDManagedAgent);
    decrypt(options: DecryptOptions): Promise<Uint8Array>;
    deriveBits(options: DeriveBitsOptions): Promise<Uint8Array>;
    encrypt(options: EncryptOptions): Promise<Uint8Array>;
    generateKey<T extends GenerateKeyOptionTypes>(options: GenerateKeyOptions<T>): Promise<GenerateKeyType<T>>;
    getKey(options: {
        keyRef: string;
    }): Promise<ManagedKey | ManagedKeyPair | undefined>;
    importKey(options: PortableKeyPair): Promise<ManagedKeyPair>;
    importKey(options: PortableKey): Promise<ManagedKey>;
    sign(options: SignOptions): Promise<Uint8Array>;
    updateKey(options: UpdateKeyOptions): Promise<boolean>;
    verify(options: VerifyOptions): Promise<boolean>;
    private getAlgorithm;
    private registerSupportedAlgorithms;
    private toCryptoKey;
    private toManagedKey;
}
//# sourceMappingURL=kms-local.d.ts.map