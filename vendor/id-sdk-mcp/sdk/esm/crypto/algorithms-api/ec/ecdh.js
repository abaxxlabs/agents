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
import { checkRequiredProperty } from '../../utils.js';
export class BaseEcdhAlgorithm extends BaseEllipticCurveAlgorithm {
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
        checkRequiredProperty({ property: 'publicKey', inObject: algorithm });
        // The publicKey object must be a CryptoKey.
        this.checkCryptoKey({ key: algorithm.publicKey });
        // The CryptoKey object must be a public key.
        this.checkKeyType({ keyType: algorithm.publicKey.type, allowedKeyType: 'public' });
        // The publicKey algorithm must match the algorithm implementation processing the operation.
        this.checkKeyAlgorithm({ keyAlgorithmName: algorithm.publicKey.algorithm.name });
        // The options object must contain a baseKey property.
        checkRequiredProperty({ property: 'baseKey', inObject: options });
        // The baseKey object must be a CryptoKey.
        this.checkCryptoKey({ key: baseKey });
        // The baseKey algorithm must match the algorithm implementation processing the operation.
        this.checkKeyAlgorithm({ keyAlgorithmName: baseKey.algorithm.name });
        // The CryptoKey object must be a private key.
        this.checkKeyType({ keyType: baseKey.type, allowedKeyType: 'private' });
        // The public and base key named curves must match.
        if (('namedCurve' in algorithm.publicKey.algorithm) && ('namedCurve' in baseKey.algorithm)
            && (algorithm.publicKey.algorithm.namedCurve !== baseKey.algorithm.namedCurve)) {
            throw new InvalidAccessError('The named curve of the publicKey and baseKey must match.');
        }
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
//# sourceMappingURL=ecdh.js.map