"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BaseEcdhAlgorithm = void 0;
const errors_js_1 = require("../errors.js");
const base_js_1 = require("./base.js");
const utils_js_1 = require("../../utils.js");
class BaseEcdhAlgorithm extends base_js_1.BaseEllipticCurveAlgorithm {
    constructor() {
        super(...arguments);
        this.name = 'ECDH';
        this.keyUsages = {
            privateKey: ['deriveBits', 'deriveKey'],
            publicKey: ['deriveBits', 'deriveKey'],
        };
    }
    checkAlgorithmOptions(options) {
        const { algorithm, baseKey } = options;
        // Algorithm specified in the operation must match the algorithm implementation processing the operation.
        this.checkAlgorithmName({ algorithmName: algorithm.name });
        // The algorithm object must contain a publicKey property.
        (0, utils_js_1.checkRequiredProperty)({ property: 'publicKey', inObject: algorithm });
        // The publicKey object must be a CryptoKey.
        this.checkCryptoKey({ key: algorithm.publicKey });
        // The CryptoKey object must be a public key.
        this.checkKeyType({ keyType: algorithm.publicKey.type, allowedKeyType: 'public' });
        // The publicKey algorithm must match the algorithm implementation processing the operation.
        this.checkKeyAlgorithm({ keyAlgorithmName: algorithm.publicKey.algorithm.name });
        // The options object must contain a baseKey property.
        (0, utils_js_1.checkRequiredProperty)({ property: 'baseKey', inObject: options });
        // The baseKey object must be a CryptoKey.
        this.checkCryptoKey({ key: baseKey });
        // The baseKey algorithm must match the algorithm implementation processing the operation.
        this.checkKeyAlgorithm({ keyAlgorithmName: baseKey.algorithm.name });
        // The CryptoKey object must be a private key.
        this.checkKeyType({ keyType: baseKey.type, allowedKeyType: 'private' });
        // The public and base key named curves must match.
        if (('namedCurve' in algorithm.publicKey.algorithm) && ('namedCurve' in baseKey.algorithm)
            && (algorithm.publicKey.algorithm.namedCurve !== baseKey.algorithm.namedCurve)) {
            throw new errors_js_1.InvalidAccessError('The named curve of the publicKey and baseKey must match.');
        }
    }
    async sign() {
        throw new errors_js_1.InvalidAccessError(`Requested operation 'sign' is not valid for ${this.name} keys.`);
    }
    async verify() {
        throw new errors_js_1.InvalidAccessError(`Requested operation 'verify' is not valid for ${this.name} keys.`);
    }
}
exports.BaseEcdhAlgorithm = BaseEcdhAlgorithm;
//# sourceMappingURL=ecdh.js.map