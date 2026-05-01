"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BaseEcdsaAlgorithm = void 0;
const errors_js_1 = require("../errors.js");
const base_js_1 = require("./base.js");
const utils_js_1 = require("../../utils.js");
class BaseEcdsaAlgorithm extends base_js_1.BaseEllipticCurveAlgorithm {
    constructor() {
        super(...arguments);
        this.name = 'ECDSA';
        this.keyUsages = {
            privateKey: ['sign'],
            publicKey: ['verify'],
        };
    }
    checkAlgorithmOptions(options) {
        const { algorithm } = options;
        // Algorithm specified in the operation must match the algorithm implementation processing the operation.
        this.checkAlgorithmName({ algorithmName: algorithm.name });
        // The algorithm object must contain a hash property.
        (0, utils_js_1.checkRequiredProperty)({ property: 'hash', inObject: algorithm });
        // The hash algorithm specified must be supported by the algorithm implementation processing the operation.
        (0, utils_js_1.checkValidProperty)({ property: algorithm.hash, allowedProperties: this.hashAlgorithms });
    }
    async deriveBits() {
        throw new errors_js_1.InvalidAccessError(`Requested operation 'deriveBits' is not valid for ${this.name} keys.`);
    }
}
exports.BaseEcdsaAlgorithm = BaseEcdsaAlgorithm;
//# sourceMappingURL=ecdsa.js.map