var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { crypto } from '@noble/hashes/crypto';
import { isWebCryptoSupported } from '../utils.js';
export class Pbkdf2 {
    static deriveKey(options) {
        return __awaiter(this, void 0, void 0, function* () {
            if (isWebCryptoSupported()) {
                return Pbkdf2.deriveKeyWithWebCrypto(options);
            }
            else {
                return Pbkdf2.deriveKeyWithNodeCrypto(options);
            }
        });
    }
    static deriveKeyWithNodeCrypto(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const { password, salt, iterations } = options;
            // Map the hash string to the node:crypto equivalent.
            const hashToNodeCryptoMap = {
                'SHA-256': 'sha256',
                'SHA-384': 'sha384',
                'SHA-512': 'sha512'
            };
            const hash = hashToNodeCryptoMap[options.hash];
            // Convert length from bits to bytes.
            const length = options.length / 8;
            // Dynamically import the `crypto` package.
            const { pbkdf2 } = yield import('node:crypto');
            return new Promise((resolve) => {
                pbkdf2(password, salt, iterations, length, hash, (err, derivedKey) => {
                    if (!err) {
                        resolve(new Uint8Array(derivedKey));
                    }
                });
            });
        });
    }
    static deriveKeyWithWebCrypto(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const { hash, password, salt, iterations, length } = options;
            // Import the password as a raw key for use with the Web Crypto API.
            const webCryptoKey = yield crypto.subtle.importKey('raw', password, { name: 'PBKDF2' }, false, ['deriveBits']);
            const derivedKeyBuffer = yield crypto.subtle.deriveBits({ name: 'PBKDF2', hash, salt, iterations }, webCryptoKey, length);
            // Convert from ArrayBuffer to Uint8Array.
            const derivedKey = new Uint8Array(derivedKeyBuffer);
            return derivedKey;
        });
    }
}
//# sourceMappingURL=pbkdf2.js.map