"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Pbkdf2 = void 0;
const crypto_1 = require("@noble/hashes/crypto");
const utils_js_1 = require("../utils.js");
class Pbkdf2 {
    static async deriveKey(options) {
        if ((0, utils_js_1.isWebCryptoSupported)()) {
            return Pbkdf2.deriveKeyWithWebCrypto(options);
        }
        else {
            return Pbkdf2.deriveKeyWithNodeCrypto(options);
        }
    }
    static async deriveKeyWithNodeCrypto(options) {
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
        const { pbkdf2 } = await import('node:crypto');
        return new Promise((resolve) => {
            pbkdf2(password, salt, iterations, length, hash, (err, derivedKey) => {
                if (!err) {
                    resolve(new Uint8Array(derivedKey));
                }
            });
        });
    }
    static async deriveKeyWithWebCrypto(options) {
        const { hash, password, salt, iterations, length } = options;
        // Import the password as a raw key for use with the Web Crypto API.
        const webCryptoKey = await crypto_1.crypto.subtle.importKey('raw', password, { name: 'PBKDF2' }, false, ['deriveBits']);
        const derivedKeyBuffer = await crypto_1.crypto.subtle.deriveBits({ name: 'PBKDF2', hash, salt, iterations }, webCryptoKey, length);
        // Convert from ArrayBuffer to Uint8Array.
        const derivedKey = new Uint8Array(derivedKeyBuffer);
        return derivedKey;
    }
}
exports.Pbkdf2 = Pbkdf2;
//# sourceMappingURL=pbkdf2.js.map