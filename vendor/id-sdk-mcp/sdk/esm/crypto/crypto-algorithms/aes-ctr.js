var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { universalTypeOf } from '../../common/index.js';
import { AesCtr } from '../crypto-primitives/index.js';
import { BaseAesCtrAlgorithm, CryptoKey } from '../algorithms-api/index.js';
export class AesCtrAlgorithm extends BaseAesCtrAlgorithm {
    decrypt(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const { algorithm, key, data } = options;
            this.checkAlgorithmOptions({ algorithm, key });
            // The secret key must be allowed to be used for 'decrypt' operations.
            this.checkKeyUsages({ keyUsages: ['decrypt'], allowedKeyUsages: key.usages });
            const plaintext = AesCtr.decrypt({
                counter: algorithm.counter,
                data: data,
                key: key.material,
                length: algorithm.length
            });
            return plaintext;
        });
    }
    encrypt(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const { algorithm, key, data } = options;
            this.checkAlgorithmOptions({ algorithm, key });
            // The secret key must be allowed to be used for 'encrypt' operations.
            this.checkKeyUsages({ keyUsages: ['encrypt'], allowedKeyUsages: key.usages });
            const ciphertext = AesCtr.encrypt({
                counter: algorithm.counter,
                data: data,
                key: key.material,
                length: algorithm.length
            });
            return ciphertext;
        });
    }
    generateKey(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const { algorithm, extractable, keyUsages } = options;
            this.checkGenerateKey({ algorithm, keyUsages });
            const secretKey = yield AesCtr.generateKey({ length: algorithm.length });
            if (universalTypeOf(secretKey) !== 'Uint8Array') {
                throw new Error('Operation failed to generate key.');
            }
            const secretCryptoKey = new CryptoKey(algorithm, extractable, secretKey, 'secret', this.keyUsages);
            return secretCryptoKey;
        });
    }
}
//# sourceMappingURL=aes-ctr.js.map