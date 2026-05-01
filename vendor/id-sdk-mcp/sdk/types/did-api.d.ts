import type { IDAgent } from './agent/index.js';
import type { DidResolutionOptions, DidResolutionResult } from './dids/index.js';
export type CustomServiceOptions = {
    serviceOptions?: {
        dwnEndpoints?: string[];
    };
};
/**
 * The DID API is used to create and resolve DIDs.
 *
 * @beta
 */
export declare class DidApi {
    private agent;
    private connectedDid;
    didUtils: any;
    constructor(options: {
        agent: IDAgent;
        connectedDid: string;
    });
    /**
     * Resolves a DID to a DID Resolution Result.
     *
     * @param didUrl - The DID or DID URL to resolve.
     * @returns A promise that resolves to the DID Resolution Result.
     */
    resolve(didUrl: string, resolutionOptions?: DidResolutionOptions): Promise<DidResolutionResult>;
    /**
     * Resolves a DID to a DID Resolution Result.
     *
     * @param options - custom service options
     * @returns A promise that resolves to the DID Resolution Result.
     */
    create(options?: CustomServiceOptions): Promise<any>;
}
//# sourceMappingURL=did-api.d.ts.map