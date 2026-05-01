var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { xchacha20 } from '@noble/ciphers/chacha';
export class XChaCha20 {
    static decrypt(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const { data, key, nonce } = options;
            const ciphertext = xchacha20(key, nonce, data);
            return ciphertext;
        });
    }
    static encrypt(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const { data, key, nonce } = options;
            const plaintext = xchacha20(key, nonce, data);
            return plaintext;
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
//# sourceMappingURL=xchacha20.js.map