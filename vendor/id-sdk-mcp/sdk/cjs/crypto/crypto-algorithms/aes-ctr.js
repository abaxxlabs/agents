"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AesCtrAlgorithm = void 0;
const index_js_1 = require("../../common/index.js");
const index_js_2 = require("../crypto-primitives/index.js");
const index_js_3 = require("../algorithms-api/index.js");
class AesCtrAlgorithm extends index_js_3.BaseAesCtrAlgorithm {
    async decrypt(options) {
        const { algorithm, key, data } = options;
        this.checkAlgorithmOptions({ algorithm, key });
        // The secret key must be allowed to be used for 'decrypt' operations.
        this.checkKeyUsages({ keyUsages: ['decrypt'], allowedKeyUsages: key.usages });
        const plaintext = index_js_2.AesCtr.decrypt({
            counter: algorithm.counter,
            data: data,
            key: key.material,
            length: algorithm.length
        });
        return plaintext;
    }
    async encrypt(options) {
        const { algorithm, key, data } = options;
        this.checkAlgorithmOptions({ algorithm, key });
        // The secret key must be allowed to be used for 'encrypt' operations.
        this.checkKeyUsages({ keyUsages: ['encrypt'], allowedKeyUsages: key.usages });
        const ciphertext = index_js_2.AesCtr.encrypt({
            counter: algorithm.counter,
            data: data,
            key: key.material,
            length: algorithm.length
        });
        return ciphertext;
    }
    async generateKey(options) {
        const { algorithm, extractable, keyUsages } = options;
        this.checkGenerateKey({ algorithm, keyUsages });
        const secretKey = await index_js_2.AesCtr.generateKey({ length: algorithm.length });
        if ((0, index_js_1.universalTypeOf)(secretKey) !== 'Uint8Array') {
            throw new Error('Operation failed to generate key.');
        }
        const secretCryptoKey = new index_js_3.CryptoKey(algorithm, extractable, secretKey, 'secret', this.keyUsages);
        return secretCryptoKey;
    }
}
exports.AesCtrAlgorithm = AesCtrAlgorithm;
//# sourceMappingURL=aes-ctr.js.map