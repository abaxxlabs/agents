"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BaseAesAlgorithm = void 0;
const index_js_1 = require("../../../common/index.js");
const utils_js_1 = require("../../utils.js");
const crypto_algorithm_js_1 = require("../crypto-algorithm.js");
const errors_js_1 = require("../errors.js");
class BaseAesAlgorithm extends crypto_algorithm_js_1.CryptoAlgorithm {
    checkGenerateKey(options) {
        const { algorithm, keyUsages } = options;
        // Algorithm specified in the operation must match the algorithm implementation processing the operation.
        this.checkAlgorithmName({ algorithmName: algorithm.name });
        // The algorithm object must contain a length property.
        (0, utils_js_1.checkRequiredProperty)({ property: 'length', inObject: algorithm });
        // The length specified must be a number.
        if ((0, index_js_1.universalTypeOf)(algorithm.length) !== 'Number') {
            throw new TypeError(`Algorithm 'length' is not of type: Number.`);
        }
        // The length specified must be one of the allowed bit lengths for AES.
        if (![128, 192, 256].includes(algorithm.length)) {
            throw new errors_js_1.OperationError(`Algorithm 'length' must be 128, 192, or 256.`);
        }
        // The key usages specified must be permitted by the algorithm implementation processing the operation.
        this.checkKeyUsages({ keyUsages, allowedKeyUsages: this.keyUsages });
    }
    async deriveBits() {
        throw new errors_js_1.InvalidAccessError(`Requested operation 'deriveBits' is not valid for ${this.name} keys.`);
    }
    async sign() {
        throw new errors_js_1.InvalidAccessError(`Requested operation 'sign' is not valid for ${this.name} keys.`);
    }
    async verify() {
        throw new errors_js_1.InvalidAccessError(`Requested operation 'verify' is not valid for ${this.name} keys.`);
    }
}
exports.BaseAesAlgorithm = BaseAesAlgorithm;
//# sourceMappingURL=base.js.map