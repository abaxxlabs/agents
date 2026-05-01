var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { InvalidAccessError } from '../errors.js';
import { CryptoAlgorithm } from '../crypto-algorithm.js';
import { checkValidProperty, checkRequiredProperty } from '../../utils.js';
export class BaseEllipticCurveAlgorithm extends CryptoAlgorithm {
    checkGenerateKey(options) {
        const { algorithm, keyUsages } = options;
        // Algorithm specified in the operation must match the algorithm implementation processing the operation.
        this.checkAlgorithmName({ algorithmName: algorithm.name });
        // The algorithm object must contain a namedCurve property.
        checkRequiredProperty({ property: 'namedCurve', inObject: algorithm });
        // The named curve specified must be supported by the algorithm implementation processing the operation.
        checkValidProperty({ property: algorithm.namedCurve, allowedProperties: this.namedCurves });
        // The key usages specified must be permitted by the algorithm implementation processing the operation.
        this.checkKeyUsages({ keyUsages, allowedKeyUsages: this.keyUsages });
    }
    decrypt() {
        return __awaiter(this, void 0, void 0, function* () {
            throw new InvalidAccessError(`Requested operation 'decrypt' is not valid for ${this.name} keys.`);
        });
    }
    encrypt() {
        return __awaiter(this, void 0, void 0, function* () {
            throw new InvalidAccessError(`Requested operation 'encrypt' is not valid for ${this.name} keys.`);
        });
    }
}
//# sourceMappingURL=base.js.map