var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import * as cryptoUtils from '../crypto/utils.js';
import { createJsonRpcRequest, parseJson } from './json-rpc.js';
export var DidRpcMethod;
(function (DidRpcMethod) {
    DidRpcMethod["Create"] = "did.create";
    DidRpcMethod["Resolve"] = "did.resolve";
})(DidRpcMethod || (DidRpcMethod = {}));
/**
 * Client used to communicate with Dwn Servers
 */
export class IDRpcClient {
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
    sendDidRequest(request) {
        return __awaiter(this, void 0, void 0, function* () {
            // URL() will throw if provided `url` is invalid.
            const url = new URL(request.url);
            const transportClient = this.transportClients.get(url.protocol);
            if (!transportClient) {
                const error = new Error(`no ${url.protocol} transport client available`);
                error.name = 'NO_TRANSPORT_CLIENT';
                throw error;
            }
            return transportClient.sendDidRequest(request);
        });
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
/**
 * Http client that can be used to communicate with Dwn Servers
 */
class HttpDwnRpcClient {
    get transportProtocols() { return ['http:', 'https:']; }
    sendDwnRequest(request) {
        return __awaiter(this, void 0, void 0, function* () {
            const requestId = cryptoUtils.randomUuid();
            const jsonRpcRequest = createJsonRpcRequest(requestId, 'dwn.processMessage', {
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
            const resp = yield fetch(request.dwnUrl, fetchOpts);
            let dwnRpcResponse;
            // check to see if response is in header first. if it is, that means the response is a ReadableStream
            let dataStream;
            const { headers } = resp;
            if (headers.has('dwn-response')) {
                const jsonRpcResponse = parseJson(headers.get('dwn-response'));
                if (jsonRpcResponse == null) {
                    throw new Error(`failed to parse json rpc response. dwn url: ${request.dwnUrl}`);
                }
                dataStream = resp.body;
                dwnRpcResponse = jsonRpcResponse;
            }
            else {
                const responseBody = yield resp.text();
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
        });
    }
}
class HttpIDRpcClient extends HttpDwnRpcClient {
    sendDidRequest(request) {
        return __awaiter(this, void 0, void 0, function* () {
            const requestId = cryptoUtils.randomUuid();
            const jsonRpcRequest = createJsonRpcRequest(requestId, request.method, {
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
                const response = yield fetch(httpRequest);
                if (response.ok) {
                    jsonRpcResponse = yield response.json();
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
        });
    }
}
//# sourceMappingURL=rpc-client.js.map