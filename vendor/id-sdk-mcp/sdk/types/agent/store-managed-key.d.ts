import type { ManagedKey, ManagedKeyPair, ManagedKeyStore, ManagedPrivateKey } from './types/managed-key.js';
import { IDManagedAgent } from './types/agent.js';
/**
 * An implementation of `ManagedKeyStore` that stores key metadata and
 * public key material in a DWN.
 *
 * An instance of this class can be used by `KeyManager` or
 * an implementation of `KeyManagementSystem`.
 */
export declare class KeyStoreDwn implements ManagedKeyStore<string, ManagedKey | ManagedKeyPair> {
    private _keyRecordProperties;
    constructor(options?: {
        schema: string;
    });
    deleteKey(options: {
        agent: IDManagedAgent;
        context?: string;
        id: string;
    }): Promise<boolean>;
    findKey(options: {
        id: string;
        agent: IDManagedAgent;
        context?: string;
    }): Promise<ManagedKey | ManagedKeyPair | undefined>;
    findKey(options: {
        alias: string;
        agent: IDManagedAgent;
        context?: string;
    }): Promise<ManagedKey | ManagedKeyPair | undefined>;
    getKey(options: {
        agent: IDManagedAgent;
        context?: string;
        id: string;
    }): Promise<ManagedKey | ManagedKeyPair | undefined>;
    importKey(options: {
        agent: IDManagedAgent;
        context?: string;
        key: ManagedKey | ManagedKeyPair;
    }): Promise<string>;
    listKeys(options: {
        agent: IDManagedAgent;
        context?: string;
    }): Promise<(ManagedKey | ManagedKeyPair)[]>;
    updateKey(options: {
        agent: IDManagedAgent;
        context?: string;
    } & Pick<ManagedKey, 'id' | 'alias' | 'metadata'>): Promise<boolean>;
    private decodeKey;
    private encodeKey;
    private getAuthor;
    private getKeyRecords;
}
/**
 * An implementation of `ManagedKeyStore` that stores key metadata and
 * public key material in memory.
 *
 * An instance of this class can be used by `KeyManager` or
 * an implementation of `KeyManagementSystem`.
 */
export declare class KeyStoreMemory implements ManagedKeyStore<string, ManagedKey | ManagedKeyPair> {
    /**
     * A private field that contains the Map used as the in-memory key-value store.
     */
    private store;
    deleteKey({ id }: {
        id: string;
    }): Promise<boolean>;
    findKey(options: {
        id: string;
    }): Promise<ManagedKey | ManagedKeyPair | undefined>;
    findKey(options: {
        alias: string;
    }): Promise<ManagedKey | ManagedKeyPair | undefined>;
    getKey({ id }: {
        id: string;
    }): Promise<ManagedKey | ManagedKeyPair | undefined>;
    importKey({ key }: {
        key: ManagedKey | ManagedKeyPair;
    }): Promise<string>;
    listKeys(): Promise<(ManagedKey | ManagedKeyPair)[]>;
    updateKey(options: Pick<ManagedKey, 'id' | 'alias' | 'metadata'>): Promise<boolean>;
}
/**
 * An implementation of `ManagedKeyStore` that stores private key
 * material in a DWN.
 *
 * An instance of this class can be used by an implementation of
 * `KeyManagementSystem`.
 */
export declare class PrivateKeyStoreDwn implements ManagedKeyStore<string, ManagedPrivateKey> {
    private _keyRecordProperties;
    deleteKey(options: {
        agent: IDManagedAgent;
        context?: string;
        id: string;
    }): Promise<boolean>;
    findKey(): Promise<ManagedPrivateKey | undefined>;
    getKey(options: {
        agent: IDManagedAgent;
        context?: string;
        id: string;
    }): Promise<ManagedPrivateKey | undefined>;
    importKey(options: {
        agent: IDManagedAgent;
        context?: string;
        key: Omit<ManagedPrivateKey, 'id'>;
    }): Promise<string>;
    listKeys(options: {
        agent: IDManagedAgent;
        context?: string;
    }): Promise<ManagedPrivateKey[]>;
    updateKey(): Promise<boolean>;
    private decodeKey;
    private encodeKey;
    private getAuthor;
    private getKeyRecords;
}
/**
 * An implementation of `ManagedKeyStore` that stores private key
 * material in memory.
 *
 * An instance of this class can be used by an implementation of
 * `KeyManagementSystem`.
 */
export declare class PrivateKeyStoreMemory implements ManagedKeyStore<string, ManagedPrivateKey> {
    /**
     * A private field that contains the Map used as the in-memory key-value store.
     */
    private store;
    deleteKey({ id }: {
        id: string;
    }): Promise<boolean>;
    findKey(): Promise<ManagedPrivateKey | undefined>;
    getKey({ id }: {
        id: string;
    }): Promise<ManagedPrivateKey | undefined>;
    importKey({ key }: {
        key: Omit<ManagedPrivateKey, 'id'>;
    }): Promise<string>;
    listKeys(): Promise<ManagedPrivateKey[]>;
    updateKey(): Promise<boolean>;
}
//# sourceMappingURL=store-managed-key.d.ts.map