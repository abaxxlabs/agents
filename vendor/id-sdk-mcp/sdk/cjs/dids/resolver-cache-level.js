"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.DidResolverCacheLevel = void 0;
const ms_1 = __importDefault(require("ms"));
const level_1 = require("level");
/**
 * Naive level-based cache for did resolution results. It just so happens that level aggressively keeps as much as it
 * can in memory when possible while also writing to the filesystem (in node runtime) and indexedDB (in browser runtime).
 * the persistent aspect is especially useful across page refreshes.
 */
class DidResolverCacheLevel {
    constructor(options = {}) {
        let { location, ttl } = options;
        location !== null && location !== void 0 ? location : (location = DidResolverCacheLevel.defaultOptions.location);
        ttl !== null && ttl !== void 0 ? ttl : (ttl = DidResolverCacheLevel.defaultOptions.ttl);
        this.cache = new level_1.Level(location);
        this.ttl = (0, ms_1.default)(ttl);
    }
    async get(did) {
        try {
            const str = await this.cache.get(did);
            const cacheWrapper = JSON.parse(str);
            if (Date.now() >= cacheWrapper.ttlMillis) {
                // defer deletion to be called in the next tick of the js event loop
                this.cache.nextTick(() => this.cache.del(did));
                return;
            }
            else {
                return cacheWrapper.value;
            }
        }
        catch (error) {
            // Don't throw when a key wasn't found.
            if (error.code === 'LEVEL_NOT_FOUND') {
                return;
            }
            throw error;
        }
    }
    set(did, value) {
        const cacheWrapper = { ttlMillis: Date.now() + this.ttl, value };
        const str = JSON.stringify(cacheWrapper);
        return this.cache.put(did, str);
    }
    delete(did) {
        return this.cache.del(did);
    }
    clear() {
        return this.cache.clear();
    }
    close() {
        return this.cache.close();
    }
}
exports.DidResolverCacheLevel = DidResolverCacheLevel;
DidResolverCacheLevel.defaultOptions = {
    location: 'data/AGENT/DID_RESOLVERCACHE',
    ttl: '15m'
};
//# sourceMappingURL=resolver-cache-level.js.map