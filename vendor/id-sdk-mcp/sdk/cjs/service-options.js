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
exports.getServiceDwnEndpoints = void 0;
const didUtils = __importStar(require("./dids/utils.js"));
/**
 * Dynamically selects DWN endpoints
 */
async function getServiceDwnEndpoints() {
    let response;
    try {
        response = await fetch('https://s3.amazonaws.com/dwn.id/.well-known/dwn.json', {
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
    const didDocument = await response.json();
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
                const healthCheck = await fetch(`${dwnUrl}/health`);
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
}
exports.getServiceDwnEndpoints = getServiceDwnEndpoints;
// function getRandomInt(min, max) {
//   min = Math.ceil(min);
//   max = Math.floor(max);
//   return Math.floor(Math.random() * (max - min)) + min;
// }
//# sourceMappingURL=service-options.js.map