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
import { Secp256k1, X25519 } from '../crypto-primitives/index.js';
import { CryptoKey, BaseEcdhAlgorithm, OperationError } from '../algorithms-api/index.js';
export class EcdhAlgorithm extends BaseEcdhAlgorithm {
    constructor() {
        super(...arguments);
        this.namedCurves = ['secp256k1', 'X25519'];
    }
    deriveBits(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const { algorithm, baseKey, length } = options;
            this.checkAlgorithmOptions({ algorithm, baseKey });
            // The base key must be allowed to be used for deriveBits operations.
            this.checkKeyUsages({ keyUsages: ['deriveBits'], allowedKeyUsages: baseKey.usages });
            // The public key must be allowed to be used for deriveBits operations.
            this.checkKeyUsages({ keyUsages: ['deriveBits'], allowedKeyUsages: algorithm.publicKey.usages });
            let sharedSecret;
            const ownKeyAlgorithm = baseKey.algorithm; // Type guard.
            switch (ownKeyAlgorithm.namedCurve) {
                case 'secp256k1': {
                    const ownPrivateKey = baseKey.material;
                    const otherPartyPublicKey = algorithm.publicKey.material;
                    sharedSecret = yield Secp256k1.sharedSecret({
                        privateKey: ownPrivateKey,
                        publicKey: otherPartyPublicKey
                    });
                    break;
                }
                case 'X25519': {
                    const ownPrivateKey = baseKey.material;
                    const otherPartyPublicKey = algorithm.publicKey.material;
                    sharedSecret = yield X25519.sharedSecret({
                        privateKey: ownPrivateKey,
                        publicKey: otherPartyPublicKey
                    });
                    break;
                }
                default:
                    throw new TypeError(`Out of range: '${ownKeyAlgorithm.namedCurve}'. Must be one of '${this.namedCurves.join(', ')}'`);
            }
            // Length is null, return the full derived secret.
            if (length === null)
                return sharedSecret;
            // If the length is not a multiple of 8, throw.
            if (length && length % 8 !== 0)
                throw new OperationError(`To be compatible with all browsers, 'length' must be a multiple of 8.`);
            // Convert length from bits to bytes.
            const lengthInBytes = length / 8;
            // If length (converted to bytes) is larger than the derived secret, throw.
            if (sharedSecret.byteLength < lengthInBytes)
                throw new OperationError(`Requested 'length' exceeds the byte length of the derived secret.`);
            // Otherwise, either return the secret or a truncated slice.
            return lengthInBytes === sharedSecret.byteLength ?
                sharedSecret :
                sharedSecret.slice(0, lengthInBytes);
        });
    }
    generateKey(options) {
        var _a;
        var _b;
        return __awaiter(this, void 0, void 0, function* () {
            const { algorithm, extractable, keyUsages } = options;
            this.checkGenerateKey({ algorithm, keyUsages });
            let keyPair;
            let cryptoKeyPair;
            switch (algorithm.namedCurve) {
                case 'secp256k1': {
                    (_a = (_b = algorithm).compressedPublicKey) !== null && _a !== void 0 ? _a : (_b.compressedPublicKey = true);
                    keyPair = yield Secp256k1.generateKeyPair({
                        compressedPublicKey: algorithm.compressedPublicKey
                    });
                    break;
                }
                case 'X25519': {
                    keyPair = yield X25519.generateKeyPair();
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
}
//# sourceMappingURL=ecdh.js.map