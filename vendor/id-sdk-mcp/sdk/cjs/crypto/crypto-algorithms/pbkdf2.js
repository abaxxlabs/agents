"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Pbkdf2Algorithm = void 0;
const index_js_1 = require("../algorithms-api/index.js");
const pbkdf2_js_1 = require("../crypto-primitives/pbkdf2.js");
class Pbkdf2Algorithm extends index_js_1.BasePbkdf2Algorithm {
    constructor() {
        super(...arguments);
        this.hashAlgorithms = ['SHA-256', 'SHA-384', 'SHA-512'];
    }
    async deriveBits(options) {
        const { algorithm, baseKey, length } = options;
        this.checkAlgorithmOptions({ algorithm, baseKey });
        // The base key must be allowed to be used for deriveBits operations.
        this.checkKeyUsages({ keyUsages: ['deriveBits'], allowedKeyUsages: baseKey.usages });
        // If the length is 0, throw.
        if (typeof length !== 'undefined' && length === 0) {
            throw new index_js_1.OperationError(`The value of 'length' cannot be zero.`);
        }
        // If the length is not a multiple of 8, throw.
        if (length && length % 8 !== 0) {
            throw new index_js_1.OperationError(`To be compatible with all browsers, 'length' must be a multiple of 8.`);
        }
        const derivedBits = pbkdf2_js_1.Pbkdf2.deriveKey({
            hash: algorithm.hash,
            iterations: algorithm.iterations,
            length: length,
            password: baseKey.material,
            salt: algorithm.salt
        });
        return derivedBits;
    }
    async importKey(options) {
        const { format, keyData, algorithm, extractable, keyUsages } = options;
        this.checkImportKey({ algorithm, format, extractable, keyUsages });
        const cryptoKey = new index_js_1.CryptoKey(algorithm, extractable, keyData, 'secret', keyUsages);
        return cryptoKey;
    }
}
exports.Pbkdf2Algorithm = Pbkdf2Algorithm;
//# sourceMappingURL=pbkdf2.js.map