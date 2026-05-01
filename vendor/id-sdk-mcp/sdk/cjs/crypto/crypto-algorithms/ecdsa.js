"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.EcdsaAlgorithm = void 0;
const utils_js_1 = require("../utils.js");
const index_js_1 = require("../crypto-primitives/index.js");
const index_js_2 = require("../algorithms-api/index.js");
class EcdsaAlgorithm extends index_js_2.BaseEcdsaAlgorithm {
    constructor() {
        super(...arguments);
        this.hashAlgorithms = ['SHA-256'];
        this.namedCurves = ['secp256k1'];
    }
    async generateKey(options) {
        var _a;
        const { algorithm, extractable, keyUsages } = options;
        this.checkGenerateKey({ algorithm, keyUsages });
        let keyPair;
        let cryptoKeyPair;
        switch (algorithm.namedCurve) {
            case 'secp256k1': {
                (_a = algorithm.compressedPublicKey) !== null && _a !== void 0 ? _a : (algorithm.compressedPublicKey = true);
                keyPair = await index_js_1.Secp256k1.generateKeyPair({ compressedPublicKey: algorithm.compressedPublicKey });
                break;
            }
            // Default case not needed because checkGenerateKey() already validates the specified namedCurve is supported.
        }
        if (!(0, utils_js_1.isBytesKeyPair)(keyPair)) {
            throw new Error('Operation failed to generate key pair.');
        }
        cryptoKeyPair = {
            privateKey: new index_js_2.CryptoKey(algorithm, extractable, keyPair.privateKey, 'private', this.keyUsages.privateKey),
            publicKey: new index_js_2.CryptoKey(algorithm, true, keyPair.publicKey, 'public', this.keyUsages.publicKey)
        };
        return cryptoKeyPair;
    }
    async sign(options) {
        const { algorithm, key, data } = options;
        this.checkAlgorithmOptions({ algorithm });
        // The key's algorithm must match the algorithm implementation processing the operation.
        this.checkKeyAlgorithm({ keyAlgorithmName: key.algorithm.name });
        // The key must be a private key.
        this.checkKeyType({ keyType: key.type, allowedKeyType: 'private' });
        // The key must be allowed to be used for sign operations.
        this.checkKeyUsages({ keyUsages: ['sign'], allowedKeyUsages: key.usages });
        let signature;
        const keyAlgorithm = key.algorithm; // Type guard.
        switch (keyAlgorithm.namedCurve) {
            case 'secp256k1': {
                signature = await index_js_1.Secp256k1.sign({ hash: algorithm.hash, key: key.material, data });
                break;
            }
            default:
                throw new TypeError(`Out of range: '${keyAlgorithm.namedCurve}'. Must be one of '${this.namedCurves.join(', ')}'`);
        }
        return signature;
    }
    async verify(options) {
        const { algorithm, key, signature, data } = options;
        this.checkAlgorithmOptions({ algorithm });
        // The key's algorithm must match the algorithm implementation processing the operation.
        this.checkKeyAlgorithm({ keyAlgorithmName: key.algorithm.name });
        // The key must be a public key.
        this.checkKeyType({ keyType: key.type, allowedKeyType: 'public' });
        // The key must be allowed to be used for verify operations.
        this.checkKeyUsages({ keyUsages: ['verify'], allowedKeyUsages: key.usages });
        let isValid;
        const keyAlgorithm = key.algorithm; // Type guard.
        switch (keyAlgorithm.namedCurve) {
            case 'secp256k1': {
                isValid = await index_js_1.Secp256k1.verify({ hash: algorithm.hash, key: key.material, signature, data });
                break;
            }
            default:
                throw new TypeError(`Out of range: '${keyAlgorithm.namedCurve}'. Must be one of '${this.namedCurves.join(', ')}'`);
        }
        return isValid;
    }
}
exports.EcdsaAlgorithm = EcdsaAlgorithm;
//# sourceMappingURL=ecdsa.js.map