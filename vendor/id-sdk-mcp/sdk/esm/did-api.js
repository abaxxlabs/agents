var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { DidMessage } from './agent/did-manager.js';
import { DidIonMethod } from './dids/index.js';
import { getServiceDwnEndpoints } from './service-options.js';
import { getServices, isDwnServiceEndpoint } from './dids/utils.js';
/**
 * The DID API is used to create and resolve DIDs.
 *
 * @beta
 */
export class DidApi {
    constructor(options) {
        this.agent = options.agent;
        this.connectedDid = options.connectedDid;
        this.didUtils = { getServices, isDwnServiceEndpoint };
    }
    /**
     * Resolves a DID to a DID Resolution Result.
     *
     * @param didUrl - The DID or DID URL to resolve.
     * @returns A promise that resolves to the DID Resolution Result.
     */
    resolve(didUrl, resolutionOptions) {
        return __awaiter(this, void 0, void 0, function* () {
            const agentResponse = yield this.agent.processDidRequest({
                messageOptions: { didUrl, resolutionOptions },
                messageType: DidMessage.Resolve
            });
            const { result } = agentResponse;
            return result;
        });
    }
    /**
     * Resolves a DID to a DID Resolution Result.
     *
     * @param options - custom service options
     * @returns A promise that resolves to the DID Resolution Result.
     */
    create(options = {}) {
        var _a, _b;
        return __awaiter(this, void 0, void 0, function* () {
            const services = [{
                    id: '#dwn',
                    type: 'DecentralizedWebNode',
                    serviceEndpoint: {
                        nodes: ((_a = options === null || options === void 0 ? void 0 : options.serviceOptions) === null || _a === void 0 ? void 0 : _a.dwnEndpoints) ? (_b = options === null || options === void 0 ? void 0 : options.serviceOptions) === null || _b === void 0 ? void 0 : _b.dwnEndpoints : yield getServiceDwnEndpoints()
                    }
                }];
            return yield DidIonMethod.create({
                services,
            });
        });
    }
}
//# sourceMappingURL=did-api.js.map