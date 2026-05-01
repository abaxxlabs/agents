"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.XChaCha20 = void 0;
const chacha_1 = require("@noble/ciphers/chacha");
class XChaCha20 {
    static async decrypt(options) {
        const { data, key, nonce } = options;
        const ciphertext = (0, chacha_1.xchacha20)(key, nonce, data);
        return ciphertext;
    }
    static async encrypt(options) {
        const { data, key, nonce } = options;
        const plaintext = (0, chacha_1.xchacha20)(key, nonce, data);
        return plaintext;
    }
    static async generateKey() {
        // Generate the secret key.
        const secretKey = crypto.getRandomValues(new Uint8Array(32));
        return secretKey;
    }
}
exports.XChaCha20 = XChaCha20;
//# sourceMappingURL=xchacha20.js.map