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
import { BaseEllipticCurveAlgorithm } from './base.js';
export class BaseEdDsaAlgorithm extends BaseEllipticCurveAlgorithm {
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
    deriveBits() {
        return __awaiter(this, void 0, void 0, function* () {
            throw new InvalidAccessError(`Requested operation 'deriveBits' is not valid for ${this.name} keys.`);
        });
    }
}
//# sourceMappingURL=eddsa.js.map