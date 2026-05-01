"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BaseEdDsaAlgorithm = void 0;
const errors_js_1 = require("../errors.js");
const base_js_1 = require("./base.js");
class BaseEdDsaAlgorithm extends base_js_1.BaseEllipticCurveAlgorithm {
    constructor() {
        super(...arguments);
        this.name = 'EdDSA';
        this.keyUsages = {
            privateKey: ['sign'],
            publicKey: ['verify'],
        };
    }
    checkAlgorithmOptions(options) {
        const { algorithm } = options;
        // Algorithm specified in the operation must match the algorithm implementation processing the operation.
        this.checkAlgorithmName({ algorithmName: algorithm.name });
    }
    async deriveBits() {
        throw new errors_js_1.InvalidAccessError(`Requested operation 'deriveBits' is not valid for ${this.name} keys.`);
    }
}
exports.BaseEdDsaAlgorithm = BaseEdDsaAlgorithm;
//# sourceMappingURL=eddsa.js.map