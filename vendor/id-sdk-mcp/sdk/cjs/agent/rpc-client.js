"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.IDRpcClient = exports.DidRpcMethod = void 0;
const cryptoUtils = __importStar(require("../crypto/utils.js"));
const json_rpc_js_1 = require("./json-rpc.js");
var DidRpcMethod;
(function (DidRpcMethod) {
    DidRpcMethod["Create"] = "did.create";
    DidRpcMethod["Resolve"] = "did.resolve";
})(DidRpcMethod || (exports.DidRpcMethod = DidRpcMethod = {}));
/**
 * Client used to communicate with Dwn Servers
 */
class IDRpcClient {
    constructor(clients = []) {
        this.transportClients = new Map();
        // include http client as default. can be overwritten for 'http:' or 'https:' if instantiator provides
        // their own.
        clients = [new HttpIDRpcClient(), ...clients];
        for (let client of clients) {
            for (let transportScheme of client.transportProtocols) {
                this.transportClients.set(transportScheme, client);
            }
        }
    }
    get transportProtocols() {
        return Array.from(this.transportClients.keys());
    }
    async sendDidRequest(request) {
        // URL() will throw if provided `url` is invalid.
        const url = new URL(request.url);
        const transportClient = this.transportClients.get(url.protocol);
        if (!transportClient) {
            const error = new Error(`no ${url.protocol} transport client available`);
            error.name = 'NO_TRANSPORT_CLIENT';
            throw error;
        }
        return transportClient.sendDidRequest(request);
    }
    sendDwnRequest(request) {
        // will throw if url is invalid
        const url = new URL(request.dwnUrl);
        const transportClient = this.transportClients.get(url.protocol);
        if (!transportClient) {
            const error = new Error(`no ${url.protocol} transport client available`);
            error.name = 'NO_TRANSPORT_CLIENT';
            throw error;
        }
        return transportClient.sendDwnRequest(request);
    }
}
exports.IDRpcClient = IDRpcClient;
/**
 * Http client that can be used to communicate with Dwn Servers
 */
class HttpDwnRpcClient {
    get transportProtocols() { return ['http:', 'https:']; }
    async sendDwnRequest(request) {
        const requestId = cryptoUtils.randomUuid();
        const jsonRpcRequest = (0, json_rpc_js_1.createJsonRpcRequest)(requestId, 'dwn.processMessage', {
            target: request.targetDid,
            message: request.message
        });
        const fetchOpts = {
            method: 'POST',
            headers: {
                'dwn-request': JSON.stringify(jsonRpcRequest)
            }
        };
        if (request.data) {
            fetchOpts.headers['content-type'] = 'application/octet-stream';
            fetchOpts['body'] = request.data;
        }
        const resp = await fetch(request.dwnUrl, fetchOpts);
        let dwnRpcResponse;
        // check to see if response is in header first. if it is, that means the response is a ReadableStream
        let dataStream;
        const { headers } = resp;
        if (headers.has('dwn-response')) {
            const jsonRpcResponse = (0, json_rpc_js_1.parseJson)(headers.get('dwn-response'));
            if (jsonRpcResponse == null) {
                throw new Error(`failed to parse json rpc response. dwn url: ${request.dwnUrl}`);
            }
            dataStream = resp.body;
            dwnRpcResponse = jsonRpcResponse;
        }
        else {
            const responseBody = await resp.text();
            dwnRpcResponse = JSON.parse(responseBody);
        }
        if (dwnRpcResponse.error) {
            const { code, message } = dwnRpcResponse.error;
            throw new Error(`(${code}) - ${message}`);
        }
        const { reply } = dwnRpcResponse.result;
        if (dataStream) {
            reply['record']['data'] = dataStream;
        }
        return reply;
    }
}
class HttpIDRpcClient extends HttpDwnRpcClient {
    async sendDidRequest(request) {
        const requestId = cryptoUtils.randomUuid();
        const jsonRpcRequest = (0, json_rpc_js_1.createJsonRpcRequest)(requestId, request.method, {
            data: request.data
        });
        const httpRequest = new Request(request.url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(jsonRpcRequest),
        });
        let jsonRpcResponse;
        try {
            const response = await fetch(httpRequest);
            if (response.ok) {
                jsonRpcResponse = await response.json();
                // If the response is an error, throw an error.
                if (jsonRpcResponse.error) {
                    const { code, message } = jsonRpcResponse.error;
                    throw new Error(`JSON RPC (${code}) - ${message}`);
                }
            }
            else {
                throw new Error(`HTTP (${response.status}) - ${response.statusText}`);
            }
        }
        catch (error) {
            throw new Error(`Error encountered while processing response from ${request.url}: ${error.message}`);
        }
        return jsonRpcResponse.result;
    }
}
//# sourceMappingURL=rpc-client.js.map