/// <reference types="node" resolution-mode="require"/>
import type { AbstractLevel } from 'abstract-level';
import type { IDManagedAgent } from './types/agent.js';
export interface SyncManager {
    agent: IDManagedAgent;
    registerIdentity(options: {
        did: string;
    }): Promise<void>;
    runNow(): Promise<void>;
    startSync(options: {
        interval: number;
    }): Promise<void>;
    stopSync(): void;
    push(): Promise<void>;
    pull(): Promise<void>;
}
type LevelDatabase = AbstractLevel<string | Buffer | Uint8Array, string, string>;
export type SyncManagerOptions = {
    agent?: IDManagedAgent;
    dataPath?: string;
    db?: LevelDatabase;
};
export declare class SyncManagerLevel implements SyncManager {
    /**
     * Holds the instance of a `IDManagedAgent` that represents the current
     * execution context for the `KeyManager`. This agent is utilized
     * to interact with other agent components. It's vital
     * to ensure this instance is set to correctly contextualize
     * operations within the broader agent framework.
     */
    private _agent?;
    private _db;
    private _syncIntervalId?;
    constructor(options?: SyncManagerOptions);
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
    clear(): Promise<void>;
    pull(): Promise<void>;
    push(): Promise<void>;
    registerIdentity(options: {
        did: string;
    }): Promise<void>;
    startSync(options: {
        interval: number;
    }): Promise<void>;
    /**
     * Run one cycle of push, pull, and outbox drain. Used by the sync interval
     * and by flushOutboxAndSync() for on-demand sync.
     */
    runNow(): Promise<void>;
    stopSync(): void;
    private enqueueOperations;
    private getDwnEventLog;
    private getDwnMessage;
    private getSyncPeerState;
    private getWatermark;
    private setWatermark;
    /**
     * The message store is used to prevent "echoes" that occur during a sync pull operation.
     * After a message is confirmed to already be synchronized on the local DWN, its CID is added
     * to the message store to ensure that any subsequent pull attempts are skipped.
     */
    private messageExists;
    private addMessage;
    private getMessageStore;
    private getWatermarkStore;
    private getPushQueue;
    private getPullQueue;
    private getDwnMessageType;
}
export {};
//# sourceMappingURL=sync-manager.d.ts.map