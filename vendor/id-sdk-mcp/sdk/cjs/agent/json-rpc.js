"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.parseJson = exports.createJsonRpcSuccessResponse = exports.createJsonRpcRequest = exports.createJsonRpcNotification = exports.createJsonRpcErrorResponse = exports.JsonRpcErrorCodes = void 0;
var JsonRpcErrorCodes;
(function (JsonRpcErrorCodes) {
    // JSON-RPC 2.0 pre-defined errors
    JsonRpcErrorCodes[JsonRpcErrorCodes["InvalidRequest"] = -32600] = "InvalidRequest";
    JsonRpcErrorCodes[JsonRpcErrorCodes["MethodNotFound"] = -32601] = "MethodNotFound";
    JsonRpcErrorCodes[JsonRpcErrorCodes["InvalidParams"] = -32602] = "InvalidParams";
    JsonRpcErrorCodes[JsonRpcErrorCodes["InternalError"] = -32603] = "InternalError";
    JsonRpcErrorCodes[JsonRpcErrorCodes["ParseError"] = -32700] = "ParseError";
    JsonRpcErrorCodes[JsonRpcErrorCodes["TransportError"] = -32300] = "TransportError";
    // App defined errors
    JsonRpcErrorCodes[JsonRpcErrorCodes["BadRequest"] = -50400] = "BadRequest";
    JsonRpcErrorCodes[JsonRpcErrorCodes["Unauthorized"] = -50401] = "Unauthorized";
    JsonRpcErrorCodes[JsonRpcErrorCodes["Forbidden"] = -50403] = "Forbidden";
})(JsonRpcErrorCodes || (exports.JsonRpcErrorCodes = JsonRpcErrorCodes = {}));
const createJsonRpcErrorResponse = (id, code, message, data) => {
    const error = { code, message };
    if (data != undefined) {
        error.data = data;
    }
    return {
        jsonrpc: '2.0',
        id,
        error,
    };
};
exports.createJsonRpcErrorResponse = createJsonRpcErrorResponse;
const createJsonRpcNotification = (method, params) => {
    return {
        jsonrpc: '2.0',
        method,
        params,
    };
};
exports.createJsonRpcNotification = createJsonRpcNotification;
const createJsonRpcRequest = (id, method, params) => {
    return {
        jsonrpc: '2.0',
        id,
        method,
        params,
    };
};
exports.createJsonRpcRequest = createJsonRpcRequest;
const createJsonRpcSuccessResponse = (id, result) => {
    return {
        jsonrpc: '2.0',
        id,
        result: result !== null && result !== void 0 ? result : null,
    };
};
exports.createJsonRpcSuccessResponse = createJsonRpcSuccessResponse;
function parseJson(text) {
    try {
        return JSON.parse(text);
    }
    catch (_a) {
        return null;
    }
}
exports.parseJson = parseJson;
//# sourceMappingURL=json-rpc.js.map