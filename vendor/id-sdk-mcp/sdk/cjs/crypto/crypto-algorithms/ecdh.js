"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.EcdhAlgorithm = void 0;
const utils_js_1 = require("../utils.js");
const index_js_1 = require("../crypto-primitives/index.js");
const index_js_2 = require("../algorithms-api/index.js");
class EcdhAlgorithm extends index_js_2.BaseEcdhAlgorithm {
    constructor() {
        super(...arguments);
        this.namedCurves = ['secp256k1', 'X25519'];
    }
    async deriveBits(options) {
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
                sharedSecret = await index_js_1.Secp256k1.sharedSecret({
                    privateKey: ownPrivateKey,
                    publicKey: otherPartyPublicKey
                });
                break;
            }
            case 'X25519': {
                const ownPrivateKey = baseKey.material;
                const otherPartyPublicKey = algorithm.publicKey.material;
                sharedSecret = await index_js_1.X25519.sharedSecret({
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
            throw new index_js_2.OperationError(`To be compatible with all browsers, 'length' must be a multiple of 8.`);
        // Convert length from bits to bytes.
        const lengthInBytes = length / 8;
        // If length (converted to bytes) is larger than the derived secret, throw.
        if (sharedSecret.byteLength < lengthInBytes)
            throw new index_js_2.OperationError(`Requested 'length' exceeds the byte length of the derived secret.`);
        // Otherwise, either return the secret or a truncated slice.
        return lengthInBytes === sharedSecret.byteLength ?
            sharedSecret :
            sharedSecret.slice(0, lengthInBytes);
    }
    async generateKey(options) {
        var _a;
        var _b;
        const { algorithm, extractable, keyUsages } = options;
        this.checkGenerateKey({ algorithm, keyUsages });
        let keyPair;
        let cryptoKeyPair;
        switch (algorithm.namedCurve) {
            case 'secp256k1': {
                (_a = (_b = algorithm).compressedPublicKey) !== null && _a !== void 0 ? _a : (_b.compressedPublicKey = true);
                keyPair = await index_js_1.Secp256k1.generateKeyPair({
                    compressedPublicKey: algorithm.compressedPublicKey
                });
                break;
            }
            case 'X25519': {
                keyPair = await index_js_1.X25519.generateKeyPair();
                break;
            }
            // Default case not needed because checkGenerateKey() already validates the specified namedCurve is supported.
        }
        if (!(0, utils_js_1.isBytesKeyPair)(keyPair)) {
            throw new Error('Operation failed to generate key pair.');
        }
        cryptoKeyPair = {
            privateKey: new index_js_2.CryptoKey(algorithm, extractable, keyPair.privateKey, 'private', this.keyUsages.privateKey),
            publicKey: new index_js_2.CryptoKey(algorithm, true, keyPair.publicKey, 'public', this.keyUsages.publicKey)
        };
        return cryptoKeyPair;
    }
}
exports.EcdhAlgorithm = EcdhAlgorithm;
//# sourceMappingURL=ecdh.js.map