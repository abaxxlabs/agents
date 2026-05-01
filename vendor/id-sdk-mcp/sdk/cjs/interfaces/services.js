"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Services = void 0;
class Services {
    constructor(options) {
        this.agent = options.agent;
        this.connectedDid = options.connectedDid;
    }
    async get(payload) {
        try {
            const headers = new Headers();
            for (let header of payload.headers) {
                headers.append(header.name, header.value);
            }
            const response = await fetch(payload.uri, {
                method: 'GET',
                mode: 'cors',
                cache: 'no-cache',
                headers: headers,
            });
            if (!response.ok) {
                return { status: response.status };
            }
            const json = await response.json();
            return json;
        }
        catch (e) {
            return { status: 400, error: e };
        }
    }
    async post(payload) {
        try {
            const headers = new Headers();
            for (let header of payload.headers) {
                headers.append(header.name, header.value);
            }
            const response = await fetch(payload.uri, {
                method: 'POST',
                mode: 'cors',
                cache: 'no-cache',
                headers: headers,
                body: JSON.stringify(payload.body),
            });
            if (!response.ok) {
                return { status: response.status };
            }
            const json = await response.json();
            return json;
        }
        catch (e) {
            return { status: 400, error: e };
        }
    }
    async put(payload) {
        try {
            const headers = new Headers();
            for (let header of payload.headers) {
                headers.append(header.name, header.value);
            }
            const response = await fetch(payload.uri, {
                method: 'PUT',
                mode: 'cors',
                cache: 'no-cache',
                headers: headers,
                body: JSON.stringify(payload.body),
            });
            if (!response.ok) {
                return { status: response.status };
            }
            const json = await response.json();
            return json;
        }
        catch (e) {
            return { status: 400 };
        }
    }
    async proxy(payload) {
        try {
            const headers = new Headers();
            for (let header of payload.headers) {
                headers.append(header.name, header.value);
            }
            const proxyRequest = {
                method: payload.method,
                mode: 'cors',
                cache: 'no-cache',
                headers: headers,
            };
            (payload === null || payload === void 0 ? void 0 : payload.body) ? proxyRequest.body = JSON.stringify(payload) : undefined;
            const response = await fetch(payload.proxy, proxyRequest);
            if (!response.ok) {
                return { status: response.status, payload };
            }
            const json = await response.json();
            return json;
        }
        catch (e) {
            return { status: 400, error: e };
        }
    }
}
exports.Services = Services;
//# sourceMappingURL=services.js.map