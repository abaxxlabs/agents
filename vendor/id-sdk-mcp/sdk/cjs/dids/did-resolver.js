"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DidResolver = void 0;
const utils_js_1 = require("./utils.js");
const resolver_cache_noop_js_1 = require("./resolver-cache-noop.js");
/**
 * The `DidResolver` class is responsible for resolving DIDs to DID documents.
 * It uses method resolvers to resolve DIDs of different methods and a cache
 * to store resolved DID documents.
 */
class DidResolver {
    /**
     * Constructs a new `DidResolver`.
     *
     * @param options - The options for constructing the `DidResolver`.
     * @param options.didResolvers - An array of `DidMethodResolver` instances.
     * @param options.cache - Optional. A cache for storing resolved DID documents. If not provided, a no-operation cache is used.
     */
    constructor(options) {
        /**
         * A map to store method resolvers against method names.
         */
        this.didResolvers = new Map();
        this.cache = options.cache || resolver_cache_noop_js_1.DidResolverCacheNoop;
        for (const resolver of options.didResolvers) {
            this.didResolvers.set(resolver.methodName, resolver);
        }
    }
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
    async resolve(didUrl, resolutionOptions) {
        const parsedDid = (0, utils_js_1.parseDid)({ didUrl });
        if (!parsedDid) {
            return {
                '@context': 'https://w3id.org/did-resolution/v1',
                didDocument: undefined,
                didDocumentMetadata: {},
                didResolutionMetadata: {
                    contentType: 'application/did+json',
                    error: 'invalidDid',
                    errorMessage: `Cannot parse DID: ${didUrl}`
                }
            };
        }
        const resolver = this.didResolvers.get(parsedDid.method);
        if (!resolver) {
            return {
                '@context': 'https://w3id.org/did-resolution/v1',
                didDocument: undefined,
                didDocumentMetadata: {},
                didResolutionMetadata: {
                    contentType: 'application/did+json',
                    error: 'methodNotSupported',
                    errorMessage: `Method not supported: ${parsedDid.method}`
                }
            };
        }
        const cachedResolutionResult = await this.cache.get(parsedDid.did);
        if (cachedResolutionResult) {
            return cachedResolutionResult;
        }
        else {
            const resolutionResult = await resolver.resolve({
                didUrl: parsedDid.did,
                resolutionOptions
            });
            await this.cache.set(parsedDid.did, resolutionResult);
            return resolutionResult;
        }
    }
}
exports.DidResolver = DidResolver;
//# sourceMappingURL=did-resolver.js.map