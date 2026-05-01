import type { Readable } from 'readable-stream';
import type { DidResolutionOptions, DidResolutionResult, PortableDid } from '../../dids/index.js';
import type { EventsGetMessage, RecordsReadReply, UnionMessageReply, MessagesGetMessage, RecordsQueryMessage, RecordsWriteMessage, RecordsDeleteMessage, ProtocolsQueryMessage, ProtocolsConfigureMessage } from '@dwn-protocol/id';
import { DidResolver } from '../../dids/index.js';
import type { Outbox } from '../outbox.js';
import type { SyncManager } from '../sync-manager.js';
import type { AppDataStore } from '../app-data-store.js';
import type { DwnRpcResponse, IDRpc } from '../rpc-client.js';
import { DidManager, DidMessage } from '../did-manager.js';
import { DwnManager } from '../dwn-manager.js';
import { KeyManager } from '../key-manager.js';
import { IdentityManager } from '../identity-manager.js';
/**
 * DID Types
 */
export type DidMessageType = keyof typeof DidMessage;
export type DidRequest = {
    messageType: DidMessageType;
    messageOptions: any;
    store?: boolean;
};
export type DidCreateMessage = {
    didMethod: string;
    didOptions?: any;
};
export type DidResolveMessage = {
    didUrl: string;
    resolutionOptions?: DidResolutionOptions;
};
export type DidResponse = {
    result?: DidResolutionResult | PortableDid;
};
/**
 * DWN Types
 */
export type DwnMessages = {
    'EventsGet': EventsGetMessage;
    'MessagesGet': MessagesGetMessage;
    'RecordsWrite': RecordsWriteMessage;
    'RecordsQuery': RecordsQueryMessage;
    'RecordsDelete': RecordsDeleteMessage;
    'ProtocolsQuery': ProtocolsQueryMessage;
    'ProtocolsConfigure': ProtocolsConfigureMessage;
};
export type DwnMessageType = keyof DwnMessages;
export type DwnRequest = {
    author: string;
    target: any;
    messageType: string;
};
/**
 * ProcessDwnRequest
 *
 * @beta
 */
export type ProcessDwnRequest = DwnRequest & {
    dataStream?: Blob | ReadableStream | Readable;
    messageOptions: unknown;
    store?: boolean;
};
export type SendDwnRequest = DwnRequest & (ProcessDwnRequest | {
    messageCid: string;
});
/**
 * DwnResponse
 *
 * @beta
 */
export type DwnResponse = {
    message?: unknown;
    messageCid?: string;
    reply: UnionMessageReply & RecordsReadReply;
};
/**
 * SendDwnResponse
 *
 * @beta
 */
export type SendDwnResponse = DwnRpcResponse;
export interface SerializableDwnMessage {
    toJSON(): string;
}
/**
 * Verifiable Credential Types
 */
export type ProcessVcRequest = {};
export type SendVcRequest = {};
export type VcResponse = {};
/**
 * Agent Types
 */
export interface IDAgent {
    agentDid: string | undefined;
    processDidRequest(request: DidRequest): Promise<DidResponse>;
    sendDidRequest(request: DidRequest): Promise<DidResponse>;
    processDwnRequest(request: ProcessDwnRequest): Promise<DwnResponse>;
    sendDwnRequest(request: SendDwnRequest): Promise<DwnResponse>;
    processVcRequest(request: ProcessVcRequest): Promise<VcResponse>;
    sendVcRequest(request: SendVcRequest): Promise<VcResponse>;
}
export interface IDManagedAgent extends IDAgent {
    appData: AppDataStore;
    didManager: DidManager;
    didResolver: DidResolver;
    dwnManager: DwnManager;
    identityManager: IdentityManager;
    keyManager: KeyManager;
    outbox?: Outbox;
    rpcClient: IDRpc;
    syncManager: SyncManager;
    firstLaunch(): Promise<boolean>;
    initialize(options: {
        passphrase: string;
    }): Promise<void>;
    start(options: {
        passphrase: string;
    }): Promise<void>;
}
//# sourceMappingURL=agent.d.ts.map