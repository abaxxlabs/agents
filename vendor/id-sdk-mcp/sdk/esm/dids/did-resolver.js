var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { parseDid } from './utils.js';
import { DidResolverCacheNoop } from './resolver-cache-noop.js';
/**
 * The `DidResolver` class is responsible for resolving DIDs to DID documents.
 * It uses method resolvers to resolve DIDs of different methods and a cache
 * to store resolved DID documents.
 */
export class DidResolver {
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
        this.cache = options.cache || DidResolverCacheNoop;
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
    resolve(didUrl, resolutionOptions) {
        return __awaiter(this, void 0, void 0, function* () {
            const parsedDid = parseDid({ didUrl });
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
            const cachedResolutionResult = yield this.cache.get(parsedDid.did);
            if (cachedResolutionResult) {
                return cachedResolutionResult;
            }
            else {
                const resolutionResult = yield resolver.resolve({
                    didUrl: parsedDid.did,
                    resolutionOptions
                });
                yield this.cache.set(parsedDid.did, resolutionResult);
                return resolutionResult;
            }
        });
    }
}
//# sourceMappingURL=did-resolver.js.map