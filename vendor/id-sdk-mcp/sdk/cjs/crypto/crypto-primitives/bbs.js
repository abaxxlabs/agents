"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Bbs = void 0;
const bbs_signatures_1 = require("@mattrglobal/bbs-signatures");
/**
 * The `Bbs` class provides an interface for BBS+ signature operations
 * using the BLS12-381 pairing-friendly curve.
 *
 * BBS+ signatures enable multi-message signing where each attribute of
 * a credential is signed as a separate message. This allows a holder
 * to derive a zero-knowledge proof that selectively discloses only
 * chosen attributes without revealing the full signed message set.
 *
 * Example usage:
 *
 * ```ts
 * const keyPair = await Bbs.generateKeyPair();
 * const messages = [
 *   new TextEncoder().encode('age=25'),
 *   new TextEncoder().encode('country=US'),
 * ];
 * const signature = await Bbs.sign({ keyPair, messages });
 *
 * const proof = await Bbs.createProof({
 *   publicKey: keyPair.publicKey,
 *   signature,
 *   messages,
 *   revealed: [1],
 *   nonce: new TextEncoder().encode('unique-nonce'),
 * });
 *
 * const isValid = await Bbs.verifyProof({
 *   publicKey: keyPair.publicKey,
 *   proof,
 *   messages: [messages[1]],
 *   nonce: new TextEncoder().encode('unique-nonce'),
 * });
 * ```
 */
class Bbs {
    /**
     * Generates a BLS12-381 G2 key pair suitable for BBS+ signatures.
     *
     * @returns A Promise resolving to a `BbsKeyPair` with 96-byte public key and 32-byte secret key.
     */
    static async generateKeyPair() {
        const keyPair = await (0, bbs_signatures_1.generateBls12381G2KeyPair)();
        return {
            publicKey: keyPair.publicKey,
            secretKey: keyPair.secretKey,
        };
    }
    /**
     * Signs a set of messages using BBS+ producing a single 112-byte signature.
     * Each message is treated as a distinct attribute that can later be
     * individually disclosed or hidden via `createProof`.
     *
     * @param options.keyPair - The BLS12-381 key pair (publicKey + secretKey).
     * @param options.messages - Array of messages (Uint8Array) to sign.
     * @returns A Promise resolving to the BBS+ signature as a Uint8Array.
     */
    static async sign(options) {
        const { keyPair, messages } = options;
        if (!messages || messages.length === 0) {
            throw new Error('At least one message is required for BBS+ signing');
        }
        const signature = await (0, bbs_signatures_1.blsSign)({
            keyPair: {
                publicKey: keyPair.publicKey,
                secretKey: keyPair.secretKey,
            },
            messages,
        });
        return signature;
    }
    /**
     * Verifies a BBS+ signature against the full set of original messages.
     *
     * @param options.publicKey - The 96-byte BLS12-381 G2 public key.
     * @param options.signature - The 112-byte BBS+ signature.
     * @param options.messages - The complete set of messages that were signed.
     * @returns A Promise resolving to `true` if the signature is valid.
     */
    static async verify(options) {
        const { publicKey, signature, messages } = options;
        const result = await (0, bbs_signatures_1.blsVerify)({
            publicKey,
            signature,
            messages,
        });
        return result.verified;
    }
    /**
     * Derives a zero-knowledge proof from a BBS+ signature that selectively
     * discloses only the messages at the specified indices. The prover
     * demonstrates knowledge of the full signature without revealing
     * hidden messages.
     *
     * @param options.publicKey - The issuer's 96-byte BLS12-381 G2 public key.
     * @param options.signature - The original 112-byte BBS+ signature.
     * @param options.messages - The complete set of messages that were signed.
     * @param options.revealed - Array of zero-based indices indicating which messages to disclose.
     * @param options.nonce - A unique nonce to bind the proof to a specific verification session.
     * @returns A Promise resolving to the derived proof as a Uint8Array.
     */
    static async createProof(options) {
        const { publicKey, signature, messages, revealed, nonce } = options;
        if (!nonce || nonce.length === 0) {
            throw new Error('A nonce is required for proof creation to prevent replay attacks');
        }
        const proof = await (0, bbs_signatures_1.blsCreateProof)({
            signature,
            publicKey,
            messages,
            nonce,
            revealed,
        });
        return proof;
    }
    /**
     * Verifies a BBS+ zero-knowledge selective disclosure proof.
     * Only the disclosed messages (those at the `revealed` indices during
     * proof creation) should be provided.
     *
     * @param options.publicKey - The issuer's 96-byte BLS12-381 G2 public key.
     * @param options.proof - The derived proof from `createProof`.
     * @param options.messages - Only the disclosed messages, in order of their original indices.
     * @param options.nonce - The same nonce used during proof creation.
     * @returns A Promise resolving to `true` if the proof is valid.
     */
    static async verifyProof(options) {
        const { publicKey, proof, messages, nonce } = options;
        const result = await (0, bbs_signatures_1.blsVerifyProof)({
            proof,
            publicKey,
            messages,
            nonce,
        });
        return result.verified;
    }
}
exports.Bbs = Bbs;
//# sourceMappingURL=bbs.js.map