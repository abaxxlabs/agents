var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
export class Services {
    constructor(options) {
        this.agent = options.agent;
        this.connectedDid = options.connectedDid;
    }
    get(payload) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const headers = new Headers();
                for (let header of payload.headers) {
                    headers.append(header.name, header.value);
                }
                const response = yield fetch(payload.uri, {
                    method: 'GET',
                    mode: 'cors',
                    cache: 'no-cache',
                    headers: headers,
                });
                if (!response.ok) {
                    return { status: response.status };
                }
                const json = yield response.json();
                return json;
            }
            catch (e) {
                return { status: 400, error: e };
            }
        });
    }
    post(payload) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const headers = new Headers();
                for (let header of payload.headers) {
                    headers.append(header.name, header.value);
                }
                const response = yield fetch(payload.uri, {
                    method: 'POST',
                    mode: 'cors',
                    cache: 'no-cache',
                    headers: headers,
                    body: JSON.stringify(payload.body),
                });
                if (!response.ok) {
                    return { status: response.status };
                }
                const json = yield response.json();
                return json;
            }
            catch (e) {
                return { status: 400, error: e };
            }
        });
    }
    put(payload) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const headers = new Headers();
                for (let header of payload.headers) {
                    headers.append(header.name, header.value);
                }
                const response = yield fetch(payload.uri, {
                    method: 'PUT',
                    mode: 'cors',
                    cache: 'no-cache',
                    headers: headers,
                    body: JSON.stringify(payload.body),
                });
                if (!response.ok) {
                    return { status: response.status };
                }
                const json = yield response.json();
                return json;
            }
            catch (e) {
                return { status: 400 };
            }
        });
    }
    proxy(payload) {
        return __awaiter(this, void 0, void 0, function* () {
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
                const response = yield fetch(payload.proxy, proxyRequest);
                if (!response.ok) {
                    return { status: response.status, payload };
                }
                const json = yield response.json();
                return json;
            }
            catch (e) {
                return { status: 400, error: e };
            }
        });
    }
}
//# sourceMappingURL=services.js.map