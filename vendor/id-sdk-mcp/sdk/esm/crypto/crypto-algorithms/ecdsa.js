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
import { Secp256k1 } from '../crypto-primitives/index.js';
import { CryptoKey, BaseEcdsaAlgorithm } from '../algorithms-api/index.js';
export class EcdsaAlgorithm extends BaseEcdsaAlgorithm {
    constructor() {
        super(...arguments);
        this.hashAlgorithms = ['SHA-256'];
        this.namedCurves = ['secp256k1'];
    }
    generateKey(options) {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
            const { algorithm, extractable, keyUsages } = options;
            this.checkGenerateKey({ algorithm, keyUsages });
            let keyPair;
            let cryptoKeyPair;
            switch (algorithm.namedCurve) {
                case 'secp256k1': {
                    (_a = algorithm.compressedPublicKey) !== null && _a !== void 0 ? _a : (algorithm.compressedPublicKey = true);
                    keyPair = yield Secp256k1.generateKeyPair({ compressedPublicKey: algorithm.compressedPublicKey });
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
                case 'secp256k1': {
                    signature = yield Secp256k1.sign({ hash: algorithm.hash, key: key.material, data });
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
                case 'secp256k1': {
                    isValid = yield Secp256k1.verify({ hash: algorithm.hash, key: key.material, signature, data });
                    break;
                }
                default:
                    throw new TypeError(`Out of range: '${keyAlgorithm.namedCurve}'. Must be one of '${this.namedCurves.join(', ')}'`);
            }
            return isValid;
        });
    }
}
//# sourceMappingURL=ecdsa.js.map