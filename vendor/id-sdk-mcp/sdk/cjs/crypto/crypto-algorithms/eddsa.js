"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.EdDsaAlgorithm = void 0;
const utils_js_1 = require("../utils.js");
const index_js_1 = require("../crypto-primitives/index.js");
const index_js_2 = require("../algorithms-api/index.js");
class EdDsaAlgorithm extends index_js_2.BaseEdDsaAlgorithm {
    constructor() {
        super(...arguments);
        this.namedCurves = ['Ed25519', 'Ed448'];
    }
    async generateKey(options) {
        const { algorithm, extractable, keyUsages } = options;
        this.checkGenerateKey({ algorithm, keyUsages });
        let keyPair;
        let cryptoKeyPair;
        switch (algorithm.namedCurve) {
            case 'Ed25519': {
                keyPair = await index_js_1.Ed25519.generateKeyPair();
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
            case 'Ed25519': {
                signature = await index_js_1.Ed25519.sign({ key: key.material, data });
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
            case 'Ed25519': {
                isValid = await index_js_1.Ed25519.verify({ key: key.material, signature, data });
                break;
            }
            default:
                throw new TypeError(`Out of range: '${keyAlgorithm.namedCurve}'. Must be one of '${this.namedCurves.join(', ')}'`);
        }
        return isValid;
    }
}
exports.EdDsaAlgorithm = EdDsaAlgorithm;
//# sourceMappingURL=eddsa.js.map