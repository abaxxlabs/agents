import type { IDCrypto } from '../types/iddwn-crypto.js';
import type { BbsKeyPair } from '../crypto-primitives/bbs.js';
export interface BbsGenerateKeyOptions extends IDCrypto.Algorithm {
    name: 'BBS';
}
export interface BbsSignOptions extends IDCrypto.Algorithm {
    name: 'BBS';
}
/**
 * High-level BBS+ signature algorithm implementing multi-message signing,
 * verification, and zero-knowledge selective disclosure proof operations.
 *
 * Unlike EdDSA/ECDSA which sign a single data buffer, BBS+ signs an array
 * of messages and supports deriving proofs that reveal only a subset.
 */
export declare class BbsAlgorithm {
    readonly name = "BBS";
    readonly keyUsages: IDCrypto.KeyPairUsage;
    /**
     * Generates a BLS12-381 G2 key pair for BBS+ operations.
     */
    generateKey(): Promise<IDCrypto.CryptoKeyPair>;
    /**
     * Signs multiple messages with BBS+ producing a single signature.
     *
     * @param options.keyPair - Raw BBS key pair (publicKey + secretKey as Uint8Array).
     * @param options.messages - Array of messages to sign.
     * @returns The BBS+ signature.
     */
    sign(options: {
        keyPair: BbsKeyPair;
        messages: Uint8Array[];
    }): Promise<Uint8Array>;
    /**
     * Verifies a BBS+ signature against the full message set.
     *
     * @param options.publicKey - The issuer's BLS12-381 G2 public key.
     * @param options.signature - The BBS+ signature to verify.
     * @param options.messages - The complete set of signed messages.
     */
    verify(options: {
        publicKey: Uint8Array;
        signature: Uint8Array;
        messages: Uint8Array[];
    }): Promise<boolean>;
    /**
     * Derives a zero-knowledge proof revealing only selected messages.
     *
     * @param options.publicKey - Issuer's public key.
     * @param options.signature - Original BBS+ signature.
     * @param options.messages - Complete message set.
     * @param options.revealed - Indices of messages to disclose.
     * @param options.nonce - Session-binding nonce.
     */
    createProof(options: {
        publicKey: Uint8Array;
        signature: Uint8Array;
        messages: Uint8Array[];
        revealed: number[];
        nonce: Uint8Array;
    }): Promise<Uint8Array>;
    /**
     * Verifies a BBS+ selective disclosure proof.
     *
     * @param options.publicKey - Issuer's public key.
     * @param options.proof - The derived proof.
     * @param options.messages - Only the disclosed messages.
     * @param options.nonce - The nonce used during proof creation.
     */
    verifyProof(options: {
        publicKey: Uint8Array;
        proof: Uint8Array;
        messages: Uint8Array[];
        nonce: Uint8Array;
    }): Promise<boolean>;
}
//# sourceMappingURL=bbs.d.ts.map