var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { BasePbkdf2Algorithm, CryptoKey, OperationError } from '../algorithms-api/index.js';
import { Pbkdf2 } from '../crypto-primitives/pbkdf2.js';
export class Pbkdf2Algorithm extends BasePbkdf2Algorithm {
    constructor() {
        super(...arguments);
        this.hashAlgorithms = ['SHA-256', 'SHA-384', 'SHA-512'];
    }
    deriveBits(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const { algorithm, baseKey, length } = options;
            this.checkAlgorithmOptions({ algorithm, baseKey });
            // The base key must be allowed to be used for deriveBits operations.
            this.checkKeyUsages({ keyUsages: ['deriveBits'], allowedKeyUsages: baseKey.usages });
            // If the length is 0, throw.
            if (typeof length !== 'undefined' && length === 0) {
                throw new OperationError(`The value of 'length' cannot be zero.`);
            }
            // If the length is not a multiple of 8, throw.
            if (length && length % 8 !== 0) {
                throw new OperationError(`To be compatible with all browsers, 'length' must be a multiple of 8.`);
            }
            const derivedBits = Pbkdf2.deriveKey({
                hash: algorithm.hash,
                iterations: algorithm.iterations,
                length: length,
                password: baseKey.material,
                salt: algorithm.salt
            });
            return derivedBits;
        });
    }
    importKey(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const { format, keyData, algorithm, extractable, keyUsages } = options;
            this.checkImportKey({ algorithm, format, extractable, keyUsages });
            const cryptoKey = new CryptoKey(algorithm, extractable, keyData, 'secret', keyUsages);
            return cryptoKey;
        });
    }
}
//# sourceMappingURL=pbkdf2.js.map