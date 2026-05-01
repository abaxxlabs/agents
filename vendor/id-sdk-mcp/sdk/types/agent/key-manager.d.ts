import type { ManagedKey, PortableKey, SignOptions, CryptoManager, VerifyOptions, DecryptOptions, EncryptOptions, ManagedKeyPair, GenerateKeyType, ManagedKeyStore, UpdateKeyOptions, DeriveBitsOptions, PortableKeyPair, GenerateKeyOptions, KeyManagementSystem, GenerateKeyOptionTypes } from './types/managed-key.js';
import { IDManagedAgent } from './types/agent.js';
export type KmsMap = {
    [name: string]: KeyManagementSystem;
};
export type KeyManagerOptions = {
    agent?: IDManagedAgent;
    kms?: KmsMap;
    store?: ManagedKeyStore<string, ManagedKey | ManagedKeyPair>;
};
/**
 * KeyManager
 *
 * This class orchestrates implementations of {@link KeyManagementSystem},
 * using a ManagedKeyStore to remember the link between a key reference,
 * its metadata, and the respective key management system that provides the
 * actual cryptographic capabilities.
 *
 * The methods of this class are used automatically by other Agent
 * components to perform their required cryptographic operations using
 * the managed keys.
 *
 * @public
 */
export declare class KeyManager implements CryptoManager {
    /**
     * Holds the instance of a `IDManagedAgent` that represents the current
     * execution context for the `KeyManager`. This agent is utilized
     * to interact with other agent components. It's vital
     * to ensure this instance is set to correctly contextualize
     * operations within the broader agent framework.
     */
    private _agent?;
    private _defaultSigningKey?;
    private _kms;
    private _store;
    constructor(options?: KeyManagerOptions);
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
    generateKey<T extends GenerateKeyOptionTypes>(options: GenerateKeyOptions<T> & {
        kms?: string;
    }): Promise<GenerateKeyType<T>>;
    getKey({ keyRef }: {
        keyRef: string;
    }): Promise<ManagedKey | ManagedKeyPair | undefined>;
    importKey(options: PortableKeyPair): Promise<ManagedKeyPair>;
    importKey(options: PortableKey): Promise<ManagedKey>;
    listKms(): string[];
    setDefaultSigningKey({ key }: {
        key: PortableKeyPair;
    }): Promise<void>;
    sign(options: SignOptions): Promise<Uint8Array>;
    updateKey(options: UpdateKeyOptions): Promise<boolean>;
    verify(options: VerifyOptions): Promise<boolean>;
    private getKms;
    private useMemoryKms;
}
//# sourceMappingURL=key-manager.d.ts.map