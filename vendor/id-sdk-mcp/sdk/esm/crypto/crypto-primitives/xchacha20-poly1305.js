var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { xchacha20poly1305 as xchacha20_poly1305 } from '@noble/ciphers/chacha';
const TAG_LENGTH = 16;
export class XChaCha20Poly1305 {
    static decrypt(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const { additionalData, data, key, nonce, tag } = options;
            // console.log(additionalData, data, key, nonce, tag);
            const xc20p = xchacha20_poly1305(key, nonce, additionalData);
            const ciphertext = new Uint8Array([...data, ...tag]);
            const plaintext = xc20p.decrypt(ciphertext);
            return plaintext;
        });
    }
    static encrypt(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const { additionalData, data, key, nonce } = options;
            const xc20p = xchacha20_poly1305(key, nonce, additionalData);
            const cipherOutput = xc20p.encrypt(data);
            const ciphertext = cipherOutput.subarray(0, -TAG_LENGTH);
            const tag = cipherOutput.subarray(-TAG_LENGTH);
            return { ciphertext, tag };
        });
    }
    static generateKey() {
        return __awaiter(this, void 0, void 0, function* () {
            // Generate the secret key.
            const secretKey = crypto.getRandomValues(new Uint8Array(32));
            return secretKey;
        });
    }
}
//# sourceMappingURL=xchacha20-poly1305.js.map