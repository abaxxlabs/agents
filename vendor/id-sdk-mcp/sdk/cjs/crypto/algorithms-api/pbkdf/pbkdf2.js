"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BasePbkdf2Algorithm = void 0;
const errors_js_1 = require("../errors.js");
const crypto_algorithm_js_1 = require("../crypto-algorithm.js");
const utils_js_1 = require("../../utils.js");
const index_js_1 = require("../../../common/index.js");
class BasePbkdf2Algorithm extends crypto_algorithm_js_1.CryptoAlgorithm {
    constructor() {
        super(...arguments);
        this.name = 'PBKDF2';
        this.keyUsages = ['deriveBits', 'deriveKey'];
    }
    checkAlgorithmOptions(options) {
        const { algorithm, baseKey } = options;
        // Algorithm specified in the operation must match the algorithm implementation processing the operation.
        this.checkAlgorithmName({ algorithmName: algorithm.name });
        // The algorithm object must contain a hash property.
        (0, utils_js_1.checkRequiredProperty)({ property: 'hash', inObject: algorithm });
        // The hash algorithm specified must be supported by the algorithm implementation processing the operation.
        (0, utils_js_1.checkValidProperty)({ property: algorithm.hash, allowedProperties: this.hashAlgorithms });
        // The algorithm object must contain a iterations property.
        (0, utils_js_1.checkRequiredProperty)({ property: 'iterations', inObject: algorithm });
        // The iterations value must a number.
        if (!((0, index_js_1.universalTypeOf)(algorithm.iterations) === 'Number')) {
            throw new TypeError(`Algorithm 'iterations' is not of type: Number.`);
        }
        // The iterations value must be greater than 0.
        if (algorithm.iterations < 1) {
            throw new errors_js_1.OperationError(`Algorithm 'iterations' must be > 0.`);
        }
        // The algorithm object must contain a salt property.
        (0, utils_js_1.checkRequiredProperty)({ property: 'salt', inObject: algorithm });
        // The salt must a Uint8Array.
        if (!((0, index_js_1.universalTypeOf)(algorithm.salt) === 'Uint8Array')) {
            throw new TypeError(`Algorithm 'salt' is not of type: Uint8Array.`);
        }
        // The options object must contain a baseKey property.
        (0, utils_js_1.checkRequiredProperty)({ property: 'baseKey', inObject: options });
        // The baseKey object must be a CryptoKey.
        this.checkCryptoKey({ key: baseKey });
        // The baseKey algorithm must match the algorithm implementation processing the operation.
        this.checkKeyAlgorithm({ keyAlgorithmName: baseKey.algorithm.name });
    }
    checkImportKey(options) {
        const { algorithm, format, extractable, keyUsages } = options;
        // Algorithm specified in the operation must match the algorithm implementation processing the operation.
        this.checkAlgorithmName({ algorithmName: algorithm.name });
        // The format specified must be 'raw'.
        if (format !== 'raw') {
            throw new SyntaxError(`Format '${format}' not supported. Only 'raw' is supported.`);
        }
        // The extractable value specified must be false.
        if (extractable !== false) {
            throw new SyntaxError(`Extractable '${extractable}' not supported. Only 'false' is supported.`);
        }
        // The key usages specified must be permitted by the algorithm implementation processing the operation.
        this.checkKeyUsages({ keyUsages, allowedKeyUsages: this.keyUsages });
    }
    async decrypt() {
        throw new errors_js_1.InvalidAccessError(`Requested operation 'decrypt' is not valid for ${this.name} keys.`);
    }
    async encrypt() {
        throw new errors_js_1.InvalidAccessError(`Requested operation 'encrypt' is not valid for ${this.name} keys.`);
    }
    async generateKey() {
        throw new errors_js_1.InvalidAccessError(`Requested operation 'generateKey' is not valid for ${this.name} keys.`);
    }
    async sign() {
        throw new errors_js_1.InvalidAccessError(`Requested operation 'sign' is not valid for ${this.name} keys.`);
    }
    async verify() {
        throw new errors_js_1.InvalidAccessError(`Requested operation 'verify' is not valid for ${this.name} keys.`);
    }
}
exports.BasePbkdf2Algorithm = BasePbkdf2Algorithm;
//# sourceMappingURL=pbkdf2.js.map