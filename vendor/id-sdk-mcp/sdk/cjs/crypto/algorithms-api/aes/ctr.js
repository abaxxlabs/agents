"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BaseAesCtrAlgorithm = void 0;
const index_js_1 = require("../../../common/index.js");
const base_js_1 = require("./base.js");
const errors_js_1 = require("../errors.js");
const utils_js_1 = require("../../utils.js");
class BaseAesCtrAlgorithm extends base_js_1.BaseAesAlgorithm {
    constructor() {
        super(...arguments);
        this.name = 'AES-CTR';
        this.keyUsages = ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'];
    }
    checkAlgorithmOptions(options) {
        const { algorithm, key } = options;
        // Algorithm specified in the operation must match the algorithm implementation processing the operation.
        this.checkAlgorithmName({ algorithmName: algorithm.name });
        // The algorithm object must contain a counter property.
        (0, utils_js_1.checkRequiredProperty)({ property: 'counter', inObject: algorithm });
        // The counter must a Uint8Array.
        if (!((0, index_js_1.universalTypeOf)(algorithm.counter) === 'Uint8Array')) {
            throw new TypeError(`Algorithm 'counter' is not of type: Uint8Array.`);
        }
        // The initial value of the counter block must be 16 bytes long (the AES block size).
        if (algorithm.counter.byteLength !== 16) {
            throw new errors_js_1.OperationError(`Algorithm 'counter' must have length: 16 bytes.`);
        }
        // The algorithm object must contain a length property.
        (0, utils_js_1.checkRequiredProperty)({ property: 'length', inObject: algorithm });
        // The length specified must be a number.
        if ((0, index_js_1.universalTypeOf)(algorithm.length) !== 'Number') {
            throw new TypeError(`Algorithm 'length' is not of type: Number.`);
        }
        // The length specified must be between 1 and 128.
        if ((algorithm.length < 1 || algorithm.length > 128)) {
            throw new errors_js_1.OperationError(`Algorithm 'length' should be in the range: 1 to 128.`);
        }
        // The options object must contain a key property.
        (0, utils_js_1.checkRequiredProperty)({ property: 'key', inObject: options });
        // The key object must be a CryptoKey.
        this.checkCryptoKey({ key });
        // The key algorithm must match the algorithm implementation processing the operation.
        this.checkKeyAlgorithm({ keyAlgorithmName: key.algorithm.name });
        // The CryptoKey object must be a secret key.
        this.checkKeyType({ keyType: key.type, allowedKeyType: 'secret' });
    }
}
exports.BaseAesCtrAlgorithm = BaseAesCtrAlgorithm;
//# sourceMappingURL=ctr.js.map