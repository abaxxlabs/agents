var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { Jose } from '../crypto/index.js';
import { ReadableWebToNodeStream } from 'readable-web-to-node-stream';
export function blobToIsomorphicNodeReadable(blob) {
    return webReadableToIsomorphicNodeReadable(blob.stream());
}
export function cryptoToManagedKey(options) {
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
export function cryptoToManagedKeyPair(options) {
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
export function cryptoToPortableKey(options) {
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
export function cryptoToPortableKeyPair(options) {
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
/**
 * Type guard function to check if the given key is a ManagedKey.
 *
 * @param key The key to check.
 * @returns True if the key is a ManagedKeyPair, false otherwise.
 */
export function isManagedKey(key) {
    return key !== undefined && 'algorithm' in key && 'extractable' in key && 'type' in key && 'usages' in key;
}
/**
 * Type guard function to check if the given key is a ManagedKeyPair.
 *
 * @param key The key to check.
 * @returns True if the key is a ManagedKeyPair, false otherwise.
 */
export function isManagedKeyPair(key) {
    return key !== undefined && 'privateKey' in key && 'publicKey' in key;
}
export function managedKeyToJwk({ key }) {
    return __awaiter(this, void 0, void 0, function* () {
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
        const jwk = yield Jose.cryptoKeyToJwk({ key: cryptoKey });
        return jwk;
    });
}
export function managedToCryptoKey({ key }) {
    const cryptoKey = {
        algorithm: key.algorithm,
        extractable: key.extractable,
        material: key.material,
        type: key.type,
        usages: key.usages
    };
    return cryptoKey;
}
export function webReadableToIsomorphicNodeReadable(webReadable) {
    return new ReadableWebToNodeStream(webReadable);
}
//# sourceMappingURL=utils.js.map