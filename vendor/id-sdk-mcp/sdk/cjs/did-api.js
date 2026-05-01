"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DidApi = void 0;
const did_manager_js_1 = require("./agent/did-manager.js");
const index_js_1 = require("./dids/index.js");
const service_options_js_1 = require("./service-options.js");
const utils_js_1 = require("./dids/utils.js");
/**
 * The DID API is used to create and resolve DIDs.
 *
 * @beta
 */
class DidApi {
    constructor(options) {
        this.agent = options.agent;
        this.connectedDid = options.connectedDid;
        this.didUtils = { getServices: utils_js_1.getServices, isDwnServiceEndpoint: utils_js_1.isDwnServiceEndpoint };
    }
    /**
     * Resolves a DID to a DID Resolution Result.
     *
     * @param didUrl - The DID or DID URL to resolve.
     * @returns A promise that resolves to the DID Resolution Result.
     */
    async resolve(didUrl, resolutionOptions) {
        const agentResponse = await this.agent.processDidRequest({
            messageOptions: { didUrl, resolutionOptions },
            messageType: did_manager_js_1.DidMessage.Resolve
        });
        const { result } = agentResponse;
        return result;
    }
    /**
     * Resolves a DID to a DID Resolution Result.
     *
     * @param options - custom service options
     * @returns A promise that resolves to the DID Resolution Result.
     */
    async create(options = {}) {
        var _a, _b;
        const services = [{
                id: '#dwn',
                type: 'DecentralizedWebNode',
                serviceEndpoint: {
                    nodes: ((_a = options === null || options === void 0 ? void 0 : options.serviceOptions) === null || _a === void 0 ? void 0 : _a.dwnEndpoints) ? (_b = options === null || options === void 0 ? void 0 : options.serviceOptions) === null || _b === void 0 ? void 0 : _b.dwnEndpoints : await (0, service_options_js_1.getServiceDwnEndpoints)()
                }
            }];
        return await index_js_1.DidIonMethod.create({
            services,
        });
    }
}
exports.DidApi = DidApi;
//# sourceMappingURL=did-api.js.map