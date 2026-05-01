var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { isBytesKeyPair } from '../utils.js';
import { Ed25519 } from '../crypto-primitives/index.js';
import { CryptoKey, BaseEdDsaAlgorithm } from '../algorithms-api/index.js';
export class EdDsaAlgorithm extends BaseEdDsaAlgorithm {
    constructor() {
        super(...arguments);
        this.namedCurves = ['Ed25519', 'Ed448'];
    }
    generateKey(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const { algorithm, extractable, keyUsages } = options;
            this.checkGenerateKey({ algorithm, keyUsages });
            let keyPair;
            let cryptoKeyPair;
            switch (algorithm.namedCurve) {
                case 'Ed25519': {
                    keyPair = yield Ed25519.generateKeyPair();
                    break;
                }
                // Default case not needed because checkGenerateKey() already validates the specified namedCurve is supported.
            }
            if (!isBytesKeyPair(keyPair)) {
                throw new Error('Operation failed to generate key pair.');
            }
            cryptoKeyPair = {
                privateKey: new CryptoKey(algorithm, extractable, keyPair.privateKey, 'private', this.keyUsages.privateKey),
                publicKey: new CryptoKey(algorithm, true, keyPair.publicKey, 'public', this.keyUsages.publicKey)
            };
            return cryptoKeyPair;
        });
    }
    sign(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const { algorithm, key, data } = options;
            this.checkAlgorithmOptions({ algorithm });
            // The key's algorithm must match the algorithm implementation processing the operation.
            this.checkKeyAlgorithm({ keyAlgorithmName: key.algorithm.name });
            // The key must be a private key.
            this.checkKeyType({ keyType: key.type, allowedKeyType: 'private' });
            // The key must be allowed to be used for sign operations.
            this.checkKeyUsages({ keyUsages: ['sign'], allowedKeyUsages: key.usages });
            let signature;
            const keyAlgorithm = key.algorithm; // Type guard.
            switch (keyAlgorithm.namedCurve) {
                case 'Ed25519': {
                    signature = yield Ed25519.sign({ key: key.material, data });
                    break;
                }
                default:
                    throw new TypeError(`Out of range: '${keyAlgorithm.namedCurve}'. Must be one of '${this.namedCurves.join(', ')}'`);
            }
            return signature;
        });
    }
    verify(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const { algorithm, key, signature, data } = options;
            this.checkAlgorithmOptions({ algorithm });
            // The key's algorithm must match the algorithm implementation processing the operation.
            this.checkKeyAlgorithm({ keyAlgorithmName: key.algorithm.name });
            // The key must be a public key.
            this.checkKeyType({ keyType: key.type, allowedKeyType: 'public' });
            // The key must be allowed to be used for verify operations.
            this.checkKeyUsages({ keyUsages: ['verify'], allowedKeyUsages: key.usages });
            let isValid;
            const keyAlgorithm = key.algorithm; // Type guard.
            switch (keyAlgorithm.namedCurve) {
                case 'Ed25519': {
                    isValid = yield Ed25519.verify({ key: key.material, signature, data });
                    break;
                }
                default:
                    throw new TypeError(`Out of range: '${keyAlgorithm.namedCurve}'. Must be one of '${this.namedCurves.join(', ')}'`);
            }
            return isValid;
        });
    }
}
//# sourceMappingURL=eddsa.js.map