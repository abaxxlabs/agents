"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.XChaCha20Poly1305 = void 0;
const chacha_1 = require("@noble/ciphers/chacha");
const TAG_LENGTH = 16;
class XChaCha20Poly1305 {
    static async decrypt(options) {
        const { additionalData, data, key, nonce, tag } = options;
        // console.log(additionalData, data, key, nonce, tag);
        const xc20p = (0, chacha_1.xchacha20poly1305)(key, nonce, additionalData);
        const ciphertext = new Uint8Array([...data, ...tag]);
        const plaintext = xc20p.decrypt(ciphertext);
        return plaintext;
    }
    static async encrypt(options) {
        const { additionalData, data, key, nonce } = options;
        const xc20p = (0, chacha_1.xchacha20poly1305)(key, nonce, additionalData);
        const cipherOutput = xc20p.encrypt(data);
        const ciphertext = cipherOutput.subarray(0, -TAG_LENGTH);
        const tag = cipherOutput.subarray(-TAG_LENGTH);
        return { ciphertext, tag };
    }
    static async generateKey() {
        // Generate the secret key.
        const secretKey = crypto.getRandomValues(new Uint8Array(32));
        return secretKey;
    }
}
exports.XChaCha20Poly1305 = XChaCha20Poly1305;
//# sourceMappingURL=xchacha20-poly1305.js.map