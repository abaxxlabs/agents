import type { SerializableDwnMessage } from './types/agent.js';
import { RecordsReadReply, UnionMessageReply } from '@abaxxtech/id';
/**
 * Interface that can be implemented to communicate with {@link IDAgent | ID Agent}
 * implementations via JSON-RPC.
 */
export interface DidRpc {
    get transportProtocols(): string[];
    sendDidRequest(request: DidRpcRequest): Promise<DidRpcResponse>;
}
export declare enum DidRpcMethod {
    Create = "did.create",
    Resolve = "did.resolve"
}
export type DidRpcRequest = {
    data: string;
    method: DidRpcMethod;
    url: string;
};
export type DidRpcResponse = {
    data?: string;
    ok: boolean;
    status: RpcStatus;
};
/**
 * interface that can be implemented to communicate with Dwn Relayers
 */
export interface DwnRpc {
    /**
     * TODO: add jsdoc
     */
    get transportProtocols(): string[];
    /**
     * TODO: add jsdoc
     * @param request
     */
    sendDwnRequest(request: DwnRpcRequest): Promise<DwnRpcResponse>;
}
/**
 * TODO: add jsdoc
 */
export type DwnRpcRequest = {
    data?: any;
    dwnUrl: string;
    message: SerializableDwnMessage | any;
    targetDid: string;
};
/**
 * TODO: add jsdoc
 */
export type DwnRpcResponse = UnionMessageReply & RecordsReadReply;
export type RpcStatus = {
    code: number;
    message: string;
};
export interface IDRpc extends DwnRpc, DidRpc {
}
/**
 * Client used to communicate with Dwn Servers
 */
export declare class IDRpcClient implements IDRpc {
    private transportClients;
    constructor(clients?: IDRpc[]);
    get transportProtocols(): string[];
    sendDidRequest(request: DidRpcRequest): Promise<DidRpcResponse>;
    sendDwnRequest(request: DwnRpcRequest): Promise<DwnRpcResponse>;
}
//# sourceMappingURL=rpc-client.d.ts.map