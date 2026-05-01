"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.webReadableToIsomorphicNodeReadable = exports.managedToCryptoKey = exports.managedKeyToJwk = exports.isManagedKeyPair = exports.isManagedKey = exports.cryptoToPortableKeyPair = exports.cryptoToPortableKey = exports.cryptoToManagedKeyPair = exports.cryptoToManagedKey = exports.blobToIsomorphicNodeReadable = void 0;
const index_js_1 = require("../crypto/index.js");
const readable_web_to_node_stream_1 = require("readable-web-to-node-stream");
function blobToIsomorphicNodeReadable(blob) {
    return webReadableToIsomorphicNodeReadable(blob.stream());
}
exports.blobToIsomorphicNodeReadable = blobToIsomorphicNodeReadable;
function cryptoToManagedKey(options) {
    var _a;
    const { cryptoKey, keyData } = options;
    const managedKey = {
        id: (_a = keyData.id) !== null && _a !== void 0 ? _a : '',
        algorithm: cryptoKey.algorithm,
        alias: keyData.alias,
        extractable: cryptoKey.extractable,
        kms: keyData.kms,
        material: (cryptoKey.type === 'public') ? cryptoKey.material : undefined,
        metadata: keyData.metadata,
        state: 'Enabled',
        type: cryptoKey.type,
        usages: cryptoKey.usages
    };
    return managedKey;
}
exports.cryptoToManagedKey = cryptoToManagedKey;
function cryptoToManagedKeyPair(options) {
    var _a, _b;
    const { cryptoKeyPair, keyData } = options;
    const privateKey = cryptoKeyPair.privateKey;
    const publicKey = cryptoKeyPair.publicKey;
    const managedKeyPair = {
        privateKey: {
            id: (_a = keyData.id) !== null && _a !== void 0 ? _a : '',
            algorithm: privateKey.algorithm,
            alias: keyData.alias,
            extractable: privateKey.extractable,
            kms: keyData.kms,
            metadata: keyData.metadata,
            state: keyData.state,
            type: privateKey.type,
            usages: privateKey.usages
        },
        publicKey: {
            id: (_b = keyData.id) !== null && _b !== void 0 ? _b : '',
            algorithm: publicKey.algorithm,
            alias: keyData.alias,
            extractable: publicKey.extractable,
            kms: keyData.kms,
            material: publicKey.material,
            metadata: keyData.metadata,
            state: keyData.state,
            type: publicKey.type,
            usages: publicKey.usages
        },
    };
    return managedKeyPair;
}
exports.cryptoToManagedKeyPair = cryptoToManagedKeyPair;
function cryptoToPortableKey(options) {
    var _a;
    const { cryptoKey, keyData } = options;
    const portableKey = {
        id: (_a = keyData.id) !== null && _a !== void 0 ? _a : '',
        algorithm: cryptoKey.algorithm,
        alias: keyData.alias,
        extractable: cryptoKey.extractable,
        kms: keyData.kms,
        material: cryptoKey.material,
        metadata: keyData.metadata,
        type: cryptoKey.type,
        usages: cryptoKey.usages
    };
    return portableKey;
}
exports.cryptoToPortableKey = cryptoToPortableKey;
function cryptoToPortableKeyPair(options) {
    var _a, _b;
    const { cryptoKeyPair, keyData } = options;
    const privateKey = cryptoKeyPair.privateKey;
    const publicKey = cryptoKeyPair.publicKey;
    const portableKeyPair = {
        privateKey: {
            id: (_a = keyData.id) !== null && _a !== void 0 ? _a : '',
            algorithm: privateKey.algorithm,
            alias: keyData.alias,
            extractable: privateKey.extractable,
            kms: keyData.kms,
            material: privateKey.material,
            metadata: keyData.metadata,
            type: privateKey.type,
            usages: privateKey.usages
        },
        publicKey: {
            id: (_b = keyData.id) !== null && _b !== void 0 ? _b : '',
            algorithm: publicKey.algorithm,
            alias: keyData.alias,
            extractable: publicKey.extractable,
            kms: keyData.kms,
            material: publicKey.material,
            metadata: keyData.metadata,
            type: publicKey.type,
            usages: publicKey.usages
        },
    };
    return portableKeyPair;
}
exports.cryptoToPortableKeyPair = cryptoToPortableKeyPair;
/**
 * Type guard function to check if the given key is a ManagedKey.
 *
 * @param key The key to check.
 * @returns True if the key is a ManagedKeyPair, false otherwise.
 */
function isManagedKey(key) {
    return key !== undefined && 'algorithm' in key && 'extractable' in key && 'type' in key && 'usages' in key;
}
exports.isManagedKey = isManagedKey;
/**
 * Type guard function to check if the given key is a ManagedKeyPair.
 *
 * @param key The key to check.
 * @returns True if the key is a ManagedKeyPair, false otherwise.
 */
function isManagedKeyPair(key) {
    return key !== undefined && 'privateKey' in key && 'publicKey' in key;
}
exports.isManagedKeyPair = isManagedKeyPair;
async function managedKeyToJwk({ key }) {
    if (key.material === undefined) {
        throw new Error(`Could not convert to JWK: 'material' is undefined.`);
    }
    const cryptoKey = {
        algorithm: key.algorithm,
        extractable: key.extractable,
        material: key.material,
        type: key.type,
        usages: key.usages
    };
    const jwk = await index_js_1.Jose.cryptoKeyToJwk({ key: cryptoKey });
    return jwk;
}
exports.managedKeyToJwk = managedKeyToJwk;
function managedToCryptoKey({ key }) {
    const cryptoKey = {
        algorithm: key.algorithm,
        extractable: key.extractable,
        material: key.material,
        type: key.type,
        usages: key.usages
    };
    return cryptoKey;
}
exports.managedToCryptoKey = managedToCryptoKey;
function webReadableToIsomorphicNodeReadable(webReadable) {
    return new readable_web_to_node_stream_1.ReadableWebToNodeStream(webReadable);
}
exports.webReadableToIsomorphicNodeReadable = webReadableToIsomorphicNodeReadable;
//# sourceMappingURL=utils.js.map