/// <reference types="node" resolution-mode="require"/>
import type { AbstractLevel } from 'abstract-level';
import type { IDManagedAgent } from './types/agent.js';
type LevelDatabase = AbstractLevel<string | Buffer | Uint8Array, string, string>;
/**
 * Serialized entry stored in the outbox for replay. Uses the same shape as
 * the RPC payload so replay is a single sendDwnRequest per endpoint.
 */
export type OutboxEntryPayload = {
    targetDid: string;
    dwnUrls: string[];
    message: Record<string, unknown>;
    dataBase64?: string;
};
export type OutboxOptions = {
    agent?: IDManagedAgent;
    dataPath?: string;
    db?: LevelDatabase;
};
/**
 * Persists outbound DWN send requests that failed due to network and replays
 * them when draining. Entries are stored in FIFO order (by key).
 */
export declare class Outbox {
    private _agent?;
    private _store;
    constructor(options?: OutboxOptions);
    get agent(): IDManagedAgent;
    set agent(agent: IDManagedAgent);
    /**
     * Enqueue a failed send for later replay. Payload must be the serializable
     * form (message object and optional data as base64).
     */
    enqueue(entry: OutboxEntryPayload): Promise<void>;
    /**
     * Try each queued item: for each entry, try each dwnUrl until one succeeds;
     * on success delete from queue; on total failure leave in queue for next drain.
     */
    drain(): Promise<void>;
    /**
     * Clear all queued entries (for tests or reset).
     */
    clear(): Promise<void>;
}
/** @deprecated Use OutboxEntryPayload */
export type OutboxEntry = OutboxEntryPayload;
export {};
//# sourceMappingURL=outbox.d.ts.map