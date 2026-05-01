import type { DidResolverCache, DidMethodResolver, DidResolutionResult, DidResolutionOptions } from './types.js';
export type DidResolverOptions = {
    didResolvers: DidMethodResolver[];
    cache?: DidResolverCache;
};
/**
 * The `DidResolver` class is responsible for resolving DIDs to DID documents.
 * It uses method resolvers to resolve DIDs of different methods and a cache
 * to store resolved DID documents.
 */
export declare class DidResolver {
    /**
     * A cache for storing resolved DID documents.
     */
    private cache;
    /**
     * A map to store method resolvers against method names.
     */
    private didResolvers;
    /**
     * Constructs a new `DidResolver`.
     *
     * @param options - The options for constructing the `DidResolver`.
     * @param options.didResolvers - An array of `DidMethodResolver` instances.
     * @param options.cache - Optional. A cache for storing resolved DID documents. If not provided, a no-operation cache is used.
     */
    constructor(options: DidResolverOptions);
    /**
     * Resolves a DID to a DID Resolution Result.
     * If the DID Resolution Result is present in the cache, it returns the cached
     * result. Otherwise, it uses the appropriate method resolver to resolve
     * the DID, stores the resolution result in the cache, and returns the
     * resolultion result.
     *
     * Note: The method signature for resolve() in this implementation must match
     * the `DidResolver` implementation in
     * {@link https://github.com/@dwn-protocol/id | @dwn-protocol/id} so that
     * IDDwn apps and the underlying DWN instance can share the same DID
     * resolution cache.
     *
     * @param didUrl - The DID or DID URL to resolve.
     * @returns A promise that resolves to the DID Resolution Result.
     */
    resolve(didUrl: string, resolutionOptions?: DidResolutionOptions): Promise<DidResolutionResult>;
}
//# sourceMappingURL=did-resolver.d.ts.map