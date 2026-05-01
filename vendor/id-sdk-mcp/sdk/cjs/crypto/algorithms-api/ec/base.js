"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BaseEllipticCurveAlgorithm = void 0;
const errors_js_1 = require("../errors.js");
const crypto_algorithm_js_1 = require("../crypto-algorithm.js");
const utils_js_1 = require("../../utils.js");
class BaseEllipticCurveAlgorithm extends crypto_algorithm_js_1.CryptoAlgorithm {
    checkGenerateKey(options) {
        const { algorithm, keyUsages } = options;
        // Algorithm specified in the operation must match the algorithm implementation processing the operation.
        this.checkAlgorithmName({ algorithmName: algorithm.name });
        // The algorithm object must contain a namedCurve property.
        (0, utils_js_1.checkRequiredProperty)({ property: 'namedCurve', inObject: algorithm });
        // The named curve specified must be supported by the algorithm implementation processing the operation.
        (0, utils_js_1.checkValidProperty)({ property: algorithm.namedCurve, allowedProperties: this.namedCurves });
        // The key usages specified must be permitted by the algorithm implementation processing the operation.
        this.checkKeyUsages({ keyUsages, allowedKeyUsages: this.keyUsages });
    }
    async decrypt() {
        throw new errors_js_1.InvalidAccessError(`Requested operation 'decrypt' is not valid for ${this.name} keys.`);
    }
    async encrypt() {
        throw new errors_js_1.InvalidAccessError(`Requested operation 'encrypt' is not valid for ${this.name} keys.`);
    }
}
exports.BaseEllipticCurveAlgorithm = BaseEllipticCurveAlgorithm;
//# sourceMappingURL=base.js.map