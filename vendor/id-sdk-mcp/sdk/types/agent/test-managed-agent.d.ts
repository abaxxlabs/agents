import type { KeyValueStore } from '../common/index.js';
import type { DidResolverCache, PortableDid } from '../dids/index.js';
import { Level } from 'level';
import { Dwn, MessageStoreLevel, DataStoreLevel, EventLogLevel } from '@abaxxtech/id';
import type { IDManagedAgent } from './types/agent.js';
import { ManagedIdentity } from './identity-manager.js';
type CreateMethodOptions = {
    agentClass: new (options: any) => IDManagedAgent;
    agentStores?: 'dwn' | 'memory';
    testDataLocation?: string;
};
type TestManagedAgentOptions = {
    agent: IDManagedAgent;
    agentStores: 'dwn' | 'memory';
    appDataStore: KeyValueStore<string, any>;
    didResolverCache: DidResolverCache;
    dwn: Dwn;
    dwnDataStore: DataStoreLevel;
    dwnEventLog: EventLogLevel;
    dwnMessageStore: MessageStoreLevel;
    syncStore: Level;
};
export declare class TestManagedAgent {
    agent: IDManagedAgent;
    agentStores: 'dwn' | 'memory';
    appDataStore: KeyValueStore<string, any>;
    didResolverCache: DidResolverCache;
    dwn: Dwn;
    dwnDataStore: DataStoreLevel;
    dwnEventLog: EventLogLevel;
    dwnMessageStore: MessageStoreLevel;
    syncStore: Level;
    constructor(options: TestManagedAgentOptions);
    clearStorage(): Promise<void>;
    closeStorage(): Promise<void>;
    static create(options: CreateMethodOptions): Promise<TestManagedAgent>;
    createAgentDid(): Promise<void>;
    createIdentity(options: {
        keyAlgorithm?: 'Ed25519' | 'secp256k1';
        testDwnUrls: string[];
    }): Promise<{
        did: PortableDid;
        identity: ManagedIdentity;
    }>;
    private static useDiskStorage;
    private static useMemoryStorage;
}
export {};
//# sourceMappingURL=test-managed-agent.d.ts.map