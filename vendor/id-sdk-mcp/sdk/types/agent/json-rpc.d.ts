export type JsonRpcId = string | number | null;
export type JsonRpcParams = any;
export type JsonRpcVersion = '2.0';
export interface JsonRpcRequest {
    jsonrpc: JsonRpcVersion;
    id?: JsonRpcId;
    method: string;
    params?: any;
}
export interface JsonRpcError {
    code: JsonRpcErrorCodes;
    message: string;
    data?: any;
}
export declare enum JsonRpcErrorCodes {
    InvalidRequest = -32600,
    MethodNotFound = -32601,
    InvalidParams = -32602,
    InternalError = -32603,
    ParseError = -32700,
    TransportError = -32300,
    BadRequest = -50400,
    Unauthorized = -50401,
    Forbidden = -50403
}
export type JsonRpcResponse = JsonRpcSuccessResponse | JsonRpcErrorResponse;
export interface JsonRpcSuccessResponse {
    jsonrpc: JsonRpcVersion;
    id: JsonRpcId;
    result: any;
    error?: never;
}
export interface JsonRpcErrorResponse {
    jsonrpc: JsonRpcVersion;
    id: JsonRpcId;
    result?: never;
    error: JsonRpcError;
}
export declare const createJsonRpcErrorResponse: (id: JsonRpcId, code: JsonRpcErrorCodes, message: string, data?: any) => JsonRpcErrorResponse;
export declare const createJsonRpcNotification: (method: string, params?: JsonRpcParams) => JsonRpcRequest;
export declare const createJsonRpcRequest: (id: JsonRpcId, method: string, params?: JsonRpcParams) => JsonRpcRequest;
export declare const createJsonRpcSuccessResponse: (id: JsonRpcId, result?: any) => JsonRpcSuccessResponse;
export declare function parseJson(text: string): object | null;
//# sourceMappingURL=json-rpc.d.ts.map