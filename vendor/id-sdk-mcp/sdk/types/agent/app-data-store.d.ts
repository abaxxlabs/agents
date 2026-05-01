import type { KeyValueStore } from '../common/index.js';
import type { IDCrypto } from '../crypto/index.js';
import { CryptoKey } from '../crypto/index.js';
export type AppDataBackup = {
    /**
     * A timestamp to record when the backup was made.
     */
    dateCreated: string;
    /**
     * The size of the backup data.
     */
    size: number;
    /**
     * Encrypted vault contents.
     */
    data: string;
};
export type AppDataStatus = {
    /**
     * Boolean indicating whether the data was successful.
     */
    initialized: boolean;
    /**
     * The timestamp of the last backup.
     */
    lastBackup: string | undefined;
    /**
     * The timestamp of the last restore.
     */
    lastRestore: string | undefined;
};
export type AppData = {
    [key: string]: any;
};
export interface AppDataStore {
    /**
     * Returns a promise that resolves to a string, which is the App DID.
     */
    getDid(): Promise<string>;
    /**
     * Returns a promise that resolves to a CryptoKey object, which
     * represents the public key associated with the App DID.
     */
    getPublicKey(): Promise<IDCrypto.CryptoKey>;
    /**
     * Returns a promise that resolves to a CryptoKey object, which
     * represents the private key associated with the App DID.
     */
    getPrivateKey(): Promise<IDCrypto.CryptoKey>;
    /**
     * Returns a promise that resolves to a AppDataStatus object, which
     * provides information about the current status of the AppData instance.
     */
    getStatus(): Promise<AppDataStatus>;
    /**
     * Initializes the AppDataStore and returns a Promise that resolves
     * to a boolean indicating whether the operation was successful.
     */
    initialize(options: {
        passphrase: string;
        keyPair: IDCrypto.CryptoKeyPair;
    }): Promise<void>;
    /**
     * Creates an encrypted backup of the current state of `AppData` and
     * returns a Promise that resolves to an `AppDataBackup` object.
     */
    backup(options: {
        passphrase: string;
    }): Promise<AppDataBackup>;
    /**
     * Restores `AppData` to the state in the provided `AppDataBackup` object.
     * It requires a passphrase to decrypt the backup and returns a Promise that
     * resolves to a boolean indicating whether the restore was successful.
     */
    restore(options: {
        backup: AppDataBackup;
        passphrase: string;
    }): Promise<boolean>;
    /**
     * Locks the `AppDataStore`, secured by a passphrase
     * that must be entered to unlock.
     */
    lock(): Promise<void>;
    /**
     * Attempts to unlock the `AppDataStore` with the provided
     * passphrase.  It returns a Promise that resolves to a
     * boolean indicating whether the unlock was successful.
     */
    unlock(options: {
        passphrase: string;
    }): Promise<boolean>;
    /**
     * Attempts to change the passphrase of the `AppDataStore`.
     * It requires the old passphrase for verification and returns
     * a Promise that resolves to a boolean indicating whether the
     * passphrase change was successful.
     */
    changePassphrase(options: {
        oldPassphrase: string;
        newPassphrase: string;
    }): Promise<boolean>;
}
export type AppDataVaultOptions = {
    keyDerivationWorkFactor?: number;
    store?: KeyValueStore<string, any>;
};
export declare class AppDataVault implements AppDataStore {
    private _keyDerivationWorkFactor;
    private _store;
    private _vaultUnlockKey;
    constructor(options?: AppDataVaultOptions);
    backup(_options: {
        passphrase: string;
    }): Promise<AppDataBackup>;
    changePassphrase(_options: {
        oldPassphrase: string;
        newPassphrase: string;
    }): Promise<boolean>;
    private generateVaultUnlockKey;
    getDid(): Promise<string>;
    getPublicKey(): Promise<CryptoKey>;
    getPrivateKey(): Promise<IDCrypto.CryptoKey>;
    getStatus(): Promise<AppDataStatus>;
    initialize(options: {
        keyPair: IDCrypto.CryptoKeyPair;
        passphrase: string;
    }): Promise<void>;
    lock(): Promise<void>;
    restore(_options: {
        backup: AppDataBackup;
        passphrase: string;
    }): Promise<boolean>;
    setStatus(options: Partial<AppDataStatus>): Promise<boolean>;
    unlock(options: {
        passphrase: string;
    }): Promise<boolean>;
}
//# sourceMappingURL=app-data-store.d.ts.map