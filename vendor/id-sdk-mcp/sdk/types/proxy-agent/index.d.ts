import type { IDRpc, DidRequest, VcResponse, DidResponse, DwnResponse, SyncManager, AppDataStore, SendVcRequest, SendDwnRequest, ProcessVcRequest, IDManagedAgent, ProcessDwnRequest } from '../agent/index.js';
import { DidResolver } from '../dids/index.js';
import { DidManager, DwnManager, KeyManager, IdentityManager } from '../agent/index.js';
export type IDProxyAgentOptions = {
    agentDid: string;
    appData: AppDataStore;
    didManager: DidManager;
    didResolver: DidResolver;
    dwnManager: DwnManager;
    identityManager: IdentityManager;
    keyManager: KeyManager;
    rpcClient: IDRpc;
    syncManager: SyncManager;
};
export declare class IDProxyAgent implements IDManagedAgent {
    agentDid: string;
    appData: AppDataStore;
    didManager: DidManager;
    didResolver: DidResolver;
    dwnManager: DwnManager;
    identityManager: IdentityManager;
    keyManager: KeyManager;
    rpcClient: IDRpc;
    syncManager: SyncManager;
    constructor(options: IDProxyAgentOptions);
    static create(options?: Partial<IDProxyAgentOptions>): Promise<IDProxyAgent>;
    firstLaunch(): Promise<boolean>;
    /**
     * Executed once the first time the Identity Agent is launched.
     * The passphrase should be input by the end-user.
     */
    initialize(options: {
        passphrase: string;
    }): Promise<void>;
    processDidRequest(_request: DidRequest): Promise<DidResponse>;
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