import type { IDRpc, DidRequest, VcResponse, DidResponse, DwnResponse, SyncManager, AppDataStore, SendVcRequest, SendDwnRequest, ProcessVcRequest, IDManagedAgent, ProcessDwnRequest } from '../agent/index.js';
import { DidResolver } from '../dids/index.js';
import { DidManager, DwnManager, KeyManager, IdentityManager, Outbox } from '../agent/index.js';
export type IDUserAgentOptions = {
    agentDid: string;
    appData: AppDataStore;
    didManager: DidManager;
    didResolver: DidResolver;
    dwnManager: DwnManager;
    identityManager: IdentityManager;
    keyManager: KeyManager;
    outbox?: Outbox;
    rpcClient: IDRpc;
    syncManager: SyncManager;
};
export declare class IDUserAgent implements IDManagedAgent {
    agentDid: string;
    appData: AppDataStore;
    didManager: DidManager;
    didResolver: DidResolver;
    dwnManager: DwnManager;
    identityManager: IdentityManager;
    keyManager: KeyManager;
    outbox?: Outbox;
    rpcClient: IDRpc;
    syncManager: SyncManager;
    constructor(options: IDUserAgentOptions);
    static create(options?: Partial<IDUserAgentOptions> & {
        queueWhenOffline?: boolean;
    }): Promise<IDUserAgent>;
    static isConnected(): boolean;
    firstLaunch(): Promise<boolean>;
    /** Executed once the first time the Agent is launched.
     * The passphrase should be input by the end-user. */
    initialize(options: {
        passphrase: string;
    }): Promise<void>;
    processDidRequest(request: DidRequest): Promise<DidResponse>;
    processDwnRequest(request: ProcessDwnRequest): Promise<DwnResponse>;
    processVcRequest(_request: ProcessVcRequest): Promise<VcResponse>;
    sendDidRequest(_request: DidRequest): Promise<DidResponse>;
    sendDwnRequest(request: SendDwnRequest): Promise<DwnResponse>;
    sendVcRequest(_request: SendVcRequest): Promise<VcResponse>;
    start(options: {
        passphrase: string;
    }): Promise<void>;
}
//# sourceMappingURL=index.d.ts.map