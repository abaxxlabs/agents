import type { IDManagedAgent } from './types/agent.js';
import type { ManagedDid } from './did-manager.js';
export interface ManagedDidStore {
    deleteDid(options: {
        did: string;
        agent?: IDManagedAgent;
        context?: string;
    }): Promise<boolean>;
    getDid(options: {
        did: string;
        agent?: IDManagedAgent;
        context?: string;
    }): Promise<ManagedDid | undefined>;
    findDid(options: {
        did: string;
        agent?: IDManagedAgent;
        context?: string;
    }): Promise<ManagedDid | undefined>;
    findDid(options: {
        alias: string;
        agent?: IDManagedAgent;
        context?: string;
    }): Promise<ManagedDid | undefined>;
    importDid(options: {
        did: ManagedDid;
        agent?: IDManagedAgent;
        context?: string;
    }): Promise<void>;
    listDids(options?: {
        agent?: IDManagedAgent;
        context?: string;
    }): Promise<ManagedDid[]>;
}
/**
 *
 */
export declare class DidStoreDwn implements ManagedDidStore {
    private _didRecordProperties;
    deleteDid(options: {
        agent: IDManagedAgent;
        context?: string;
        did: string;
    }): Promise<boolean>;
    findDid(options: {
        agent: IDManagedAgent;
        context?: string;
        did: string;
    }): Promise<ManagedDid | undefined>;
    findDid(options: {
        agent: IDManagedAgent;
        context?: string;
        alias: string;
    }): Promise<ManagedDid | undefined>;
    getDid(options: {
        agent: IDManagedAgent;
        context?: string;
        did: string;
    }): Promise<ManagedDid | undefined>;
    importDid(options: {
        agent: IDManagedAgent;
        context?: string;
        did: ManagedDid;
    }): Promise<void>;
    listDids(options: {
        agent: IDManagedAgent;
        context?: string;
    }): Promise<ManagedDid[]>;
    private getAuthor;
}
/**
 *
 */
export declare class DidStoreMemory implements ManagedDidStore {
    /**
     * A private field that contains the Map used as the in-memory key-value store.
     */
    private store;
    deleteDid({ did }: {
        did: string;
    }): Promise<boolean>;
    getDid({ did }: {
        did: string;
    }): Promise<ManagedDid | undefined>;
    findDid(options: {
        did: string;
    }): Promise<ManagedDid | undefined>;
    findDid(options: {
        alias: string;
    }): Promise<ManagedDid | undefined>;
    importDid(options: {
        did: ManagedDid;
    }): Promise<void>;
    listDids(): Promise<ManagedDid[]>;
}
//# sourceMappingURL=store-managed-did.d.ts.map