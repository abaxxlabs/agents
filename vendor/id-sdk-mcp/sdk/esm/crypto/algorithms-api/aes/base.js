var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { universalTypeOf } from '../../../common/index.js';
import { checkRequiredProperty } from '../../utils.js';
import { CryptoAlgorithm } from '../crypto-algorithm.js';
import { InvalidAccessError, OperationError } from '../errors.js';
export class BaseAesAlgorithm extends CryptoAlgorithm {
    checkGenerateKey(options) {
        const { algorithm, keyUsages } = options;
        // Algorithm specified in the operation must match the algorithm implementation processing the operation.
        this.checkAlgorithmName({ algorithmName: algorithm.name });
        // The algorithm object must contain a length property.
        checkRequiredProperty({ property: 'length', inObject: algorithm });
        // The length specified must be a number.
        if (universalTypeOf(algorithm.length) !== 'Number') {
            throw new TypeError(`Algorithm 'length' is not of type: Number.`);
        }
        // The length specified must be one of the allowed bit lengths for AES.
        if (![128, 192, 256].includes(algorithm.length)) {
            throw new OperationError(`Algorithm 'length' must be 128, 192, or 256.`);
        }
        // The key usages specified must be permitted by the algorithm implementation processing the operation.
        this.checkKeyUsages({ keyUsages, allowedKeyUsages: this.keyUsages });
    }
    deriveBits() {
        return __awaiter(this, void 0, void 0, function* () {
            throw new InvalidAccessError(`Requested operation 'deriveBits' is not valid for ${this.name} keys.`);
        });
    }
    sign() {
        return __awaiter(this, void 0, void 0, function* () {
            throw new InvalidAccessError(`Requested operation 'sign' is not valid for ${this.name} keys.`);
        });
    }
    verify() {
        return __awaiter(this, void 0, void 0, function* () {
            throw new InvalidAccessError(`Requested operation 'verify' is not valid for ${this.name} keys.`);
        });
    }
}
//# sourceMappingURL=base.js.map