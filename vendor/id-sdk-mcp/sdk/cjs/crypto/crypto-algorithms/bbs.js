"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BbsAlgorithm = void 0;
const bbs_js_1 = require("../crypto-primitives/bbs.js");
const index_js_1 = require("../algorithms-api/index.js");
/**
 * High-level BBS+ signature algorithm implementing multi-message signing,
 * verification, and zero-knowledge selective disclosure proof operations.
 *
 * Unlike EdDSA/ECDSA which sign a single data buffer, BBS+ signs an array
 * of messages and supports deriving proofs that reveal only a subset.
 */
class BbsAlgorithm {
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
    async generateKey() {
        const keyPair = await bbs_js_1.Bbs.generateKeyPair();
        const algorithm = { name: 'BBS' };
        const cryptoKeyPair = {
            privateKey: new index_js_1.CryptoKey(algorithm, true, keyPair.secretKey, 'private', ['sign']),
            publicKey: new index_js_1.CryptoKey(algorithm, true, keyPair.publicKey, 'public', ['verify']),
        };
        return cryptoKeyPair;
    }
    /**
     * Signs multiple messages with BBS+ producing a single signature.
     *
     * @param options.keyPair - Raw BBS key pair (publicKey + secretKey as Uint8Array).
     * @param options.messages - Array of messages to sign.
     * @returns The BBS+ signature.
     */
    async sign(options) {
        return bbs_js_1.Bbs.sign(options);
    }
    /**
     * Verifies a BBS+ signature against the full message set.
     *
     * @param options.publicKey - The issuer's BLS12-381 G2 public key.
     * @param options.signature - The BBS+ signature to verify.
     * @param options.messages - The complete set of signed messages.
     */
    async verify(options) {
        return bbs_js_1.Bbs.verify(options);
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
    async createProof(options) {
        return bbs_js_1.Bbs.createProof(options);
    }
    /**
     * Verifies a BBS+ selective disclosure proof.
     *
     * @param options.publicKey - Issuer's public key.
     * @param options.proof - The derived proof.
     * @param options.messages - Only the disclosed messages.
     * @param options.nonce - The nonce used during proof creation.
     */
    async verifyProof(options) {
        return bbs_js_1.Bbs.verifyProof(options);
    }
}
exports.BbsAlgorithm = BbsAlgorithm;
//# sourceMappingURL=bbs.js.map