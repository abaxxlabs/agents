var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import * as didUtils from './dids/utils.js';
/**
 * Dynamically selects DWN endpoints
 */
export function getServiceDwnEndpoints() {
    return __awaiter(this, void 0, void 0, function* () {
        let response;
        try {
            response = yield fetch('https://s3.amazonaws.com/dwn.id/.well-known/dwn.json', {
                method: 'GET',
                mode: 'cors',
                cache: 'no-cache',
                headers: {
                    'Accept': '*/*',
                    'Content-Type': 'application/json',
                },
            });
            // console.log('response', response);
            if (!response.ok) {
                throw new Error(`HTTP Error: ${response.status} ${response.statusText}`);
            }
        }
        catch (error) {
            // console.warn('failed to get dwn endpoints:', error.message);
            return [];
        }
        const didDocument = yield response.json();
        const [dwnService] = didUtils.getServices({ didDocument, id: '#dwn', type: 'DecentralizedWebNode' });
        // allocate nodes for a user.
        const dwnEndpoints = new Set();
        if ('serviceEndpoint' in dwnService
            && !Array.isArray(dwnService.serviceEndpoint)
            && typeof dwnService.serviceEndpoint !== 'string'
            && Array.isArray(dwnService.serviceEndpoint.nodes)) {
            const dwnUrls = dwnService.serviceEndpoint.nodes;
            const numNodesToAllocate = Math.min(dwnUrls.length, 3);
            for (let attempts = 0; attempts < dwnUrls.length && dwnEndpoints.size <= numNodesToAllocate; attempts += 1) {
                // when we have more relayers we can dynamically choose up to 3
                // const nodeIdx = getRandomInt(0, dwnUrls.length);
                const dwnUrl = dwnUrls[attempts];
                try {
                    const healthCheck = yield fetch(`${dwnUrl}/health`);
                    if (healthCheck.ok) {
                        dwnEndpoints.add(dwnUrl);
                    }
                }
                catch (error) {
                    // Ignore healthcheck failure and try the next node.
                }
            }
        }
        return Array.from(dwnEndpoints);
    });
}
// function getRandomInt(min, max) {
//   min = Math.ceil(min);
//   max = Math.floor(max);
//   return Math.floor(Math.random() * (max - min)) + min;
// }
//# sourceMappingURL=service-options.js.map