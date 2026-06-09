import type { AppDataStore, IDAgent } from './agent/index.js';
import { DwnApi } from './dwn-api.js';
import { DidApi } from './did-api.js';
import { DidKeyMethod, DidDhtMethod, DidIonMethod } from './dids/index.js';
import { Metadata } from './interfaces/metadata.js';
import { Queue } from './interfaces/queue.js';
import { Services } from './interfaces/services.js';
import { Transactions } from './interfaces/transactions.js';
import { Jose } from './crypto/index.js';
import { VcApi } from './vc-api.js';
import { Jws } from '@abaxxtech/id';
/**
 * Override defaults.
 */
export type ServiceOptions = {
    dwnEndpoints?: string[];
    dhtRelayUrl?: string;
};
/**
 * Optional overrides that can be provided when calling {@link IDDwn.connect}.
 */
export type IDConnectOptions = {
    /** Provide a {@link IDAgent} implementation. Defaults to creating a local
     * {@link IDUserAgent} if one isn't provided */
    agent?: IDAgent;
    /** Provide an instance of a {@link AppDataStore} implementation. Defaults to
     * a LevelDB-backed store with an insecure, static unlock passphrase if one
     * isn't provided. To allow the app user to enter a secure passphrase of
     * their choosing, provide an initialized {@link AppDataStore} instance. */
    appData?: AppDataStore;
    connectedDid?: string;
    /** Specify the DID method to use when creating a new identity.
     * Defaults to 'ion'. Supported methods: 'ion', 'dht', 'key' */
    didMethod?: 'ion' | 'dht' | 'key';
    /** Enable synchronization of DWN records between local and remote DWNs.
     * Sync defaults to running every 30 seconds and can be set to any value accepted by `ms()`.
     * To disable sync set to 'off'. */
    sync?: string;
    /** When true (default), failed outbound DWN sends are queued in an outbox and replayed when online.
     * Set to false to throw on send failure instead of queuing. */
    queueWhenOffline?: boolean;
    /** When true and in a browser, run sync and outbox drain immediately when the window 'online' event fires.
     * Default false. In Node, use flushOutboxAndSync() after your own connectivity check. */
    flushWhenOnline?: boolean;
    /** Override defaults service options.
     * See {@link ServiceOptions} for available options. */
    serviceOptions?: ServiceOptions;
    passphrase?: string;
};
/**
 * @see {@link IDConnectOptions}
 */
type IDOptions = {
    agent: IDAgent;
    connectedDid: string;
};
type UtilsOptions = {
    DidKeyMethod: DidKeyMethod;
    DidDhtMethod: DidDhtMethod;
    DidIonMethod: DidIonMethod;
    Jose: Jose;
    Jws: Jws;
};
export declare class IDDwn {
    agent: IDAgent;
    private connectedDid;
    did: DidApi;
    dwn: DwnApi;
    metadata: Metadata;
    jose: Jose;
    protocol: any;
    queue: Queue;
    services: Services;
    transactions: Transactions;
    utils: UtilsOptions;
    vc: VcApi;
    constructor(options: IDOptions);
    /**
     * Connects to a {@link IDAgent}. Defaults to creating a local {@link IDUserAgent}
     * if one isn't provided.
     *
     * @param options - optional overrides
     * @returns
     */
    static connect(options?: IDConnectOptions): Promise<{
        iddwn: IDDwn;
        did: string;
    }>;
    /**
     * Run outbox drain then one sync cycle (push + pull). Use when back online
     * to flush queued sends and sync immediately without waiting for the next interval.
     */
    flushOutboxAndSync(): Promise<void>;
}
export {};
//# sourceMappingURL=iddwn.d.ts.map