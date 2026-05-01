var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { Bbs } from '../crypto-primitives/bbs.js';
import { CryptoKey } from '../algorithms-api/index.js';
/**
 * High-level BBS+ signature algorithm implementing multi-message signing,
 * verification, and zero-knowledge selective disclosure proof operations.
 *
 * Unlike EdDSA/ECDSA which sign a single data buffer, BBS+ signs an array
 * of messages and supports deriving proofs that reveal only a subset.
 */
export class BbsAlgorithm {
    constructor() {
        this.name = 'BBS';
        this.keyUsages = {
            privateKey: ['sign'],
            publicKey: ['verify'],
        };
    }
    /**
     * Generates a BLS12-381 G2 key pair for BBS+ operations.
     */
    generateKey() {
        return __awaiter(this, void 0, void 0, function* () {
            const keyPair = yield Bbs.generateKeyPair();
            const algorithm = { name: 'BBS' };
            const cryptoKeyPair = {
                privateKey: new CryptoKey(algorithm, true, keyPair.secretKey, 'private', ['sign']),
                publicKey: new CryptoKey(algorithm, true, keyPair.publicKey, 'public', ['verify']),
            };
            return cryptoKeyPair;
        });
    }
    /**
     * Signs multiple messages with BBS+ producing a single signature.
     *
     * @param options.keyPair - Raw BBS key pair (publicKey + secretKey as Uint8Array).
     * @param options.messages - Array of messages to sign.
     * @returns The BBS+ signature.
     */
    sign(options) {
        return __awaiter(this, void 0, void 0, function* () {
            return Bbs.sign(options);
        });
    }
    /**
     * Verifies a BBS+ signature against the full message set.
     *
     * @param options.publicKey - The issuer's BLS12-381 G2 public key.
     * @param options.signature - The BBS+ signature to verify.
     * @param options.messages - The complete set of signed messages.
     */
    verify(options) {
        return __awaiter(this, void 0, void 0, function* () {
            return Bbs.verify(options);
        });
    }
    /**
     * Derives a zero-knowledge proof revealing only selected messages.
     *
     * @param options.publicKey - Issuer's public key.
     * @param options.signature - Original BBS+ signature.
     * @param options.messages - Complete message set.
     * @param options.revealed - Indices of messages to disclose.
     * @param options.nonce - Session-binding nonce.
     */
    createProof(options) {
        return __awaiter(this, void 0, void 0, function* () {
            return Bbs.createProof(options);
        });
    }
    /**
     * Verifies a BBS+ selective disclosure proof.
     *
     * @param options.publicKey - Issuer's public key.
     * @param options.proof - The derived proof.
     * @param options.messages - Only the disclosed messages.
     * @param options.nonce - The nonce used during proof creation.
     */
    verifyProof(options) {
        return __awaiter(this, void 0, void 0, function* () {
            return Bbs.verifyProof(options);
        });
    }
}
//# sourceMappingURL=bbs.js.map