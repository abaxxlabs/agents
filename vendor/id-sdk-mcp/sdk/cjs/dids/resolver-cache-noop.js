"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DidResolverCacheNoop = void 0;
/**
 * no-op cache that is used as the default cache for did-resolver.
 * The motivation behind using a no-op cache as the default stems from
 * the desire to maximize the potential for this library to be used
 * in as many JS runtimes as possible
 */
exports.DidResolverCacheNoop = {
    get: function (_key) {
        return null;
    },
    set: function (_key, _value) {
        return null;
    },
    delete: function (_key) {
        return null;
    },
    clear: function () {
        return null;
    },
    close: function () {
        return null;
    }
};
//# sourceMappingURL=resolver-cache-noop.js.map