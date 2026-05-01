import type { IDManagedAgent } from './types/agent.js';
import type { ManagedIdentity } from './identity-manager.js';
export interface ManagedIdentityStore {
    deleteIdentity(options: {
        did: string;
        agent?: IDManagedAgent;
        context?: string;
    }): Promise<boolean>;
    getIdentity(options: {
        did: string;
        agent?: IDManagedAgent;
        context?: string;
    }): Promise<ManagedIdentity | undefined>;
    importIdentity(options: {
        identity: ManagedIdentity;
        agent?: IDManagedAgent;
        context?: string;
    }): Promise<void>;
    listIdentities(options?: {
        agent?: IDManagedAgent;
        context?: string;
    }): Promise<ManagedIdentity[]>;
}
/**
 *
 */
export declare class IdentityStoreDwn implements ManagedIdentityStore {
    private _identityRecordProperties;
    deleteIdentity(options: {
        agent: IDManagedAgent;
        context?: string;
        did: string;
    }): Promise<boolean>;
    getIdentity(options: {
        agent: IDManagedAgent;
        context?: string;
        did: string;
    }): Promise<ManagedIdentity | undefined>;
    importIdentity(options: {
        agent: IDManagedAgent;
        context?: string;
        identity: ManagedIdentity;
    }): Promise<void>;
    listIdentities(options: {
        agent: IDManagedAgent;
        context?: string;
    }): Promise<ManagedIdentity[]>;
    private getAuthor;
}
/**
 *
 */
export declare class IdentityStoreMemory implements ManagedIdentityStore {
    /**
     * A private field that contains the Map used as the in-memory key-value store.
     */
    private store;
    deleteIdentity({ did }: {
        did: string;
    }): Promise<boolean>;
    getIdentity({ did }: {
        did: string;
    }): Promise<ManagedIdentity | undefined>;
    importIdentity(options: {
        identity: ManagedIdentity;
    }): Promise<void>;
    listIdentities(): Promise<ManagedIdentity[]>;
}
//# sourceMappingURL=store-managed-identity.d.ts.map