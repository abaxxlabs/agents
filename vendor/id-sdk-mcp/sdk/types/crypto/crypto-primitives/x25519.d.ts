import type { BytesKeyPair } from '../types/crypto-key.js';
/**
 * The `X25519` class provides an interface for X25519 (Curve25519) key pair
 * generation, public key computation, and shared secret computation. The class
 * uses the '@noble/curves/ed25519' package for the cryptographic operations.
 *
 * All methods of this class are asynchronous and return Promises. They all use
 * the Uint8Array type for keys and data, providing a consistent
 * interface for working with binary data.
 *
 * Example usage:
 *
 * ```ts
 * const ownKeyPair = await X25519.generateKeyPair();
 * const otherPartyKeyPair = await X25519.generateKeyPair();
 * const sharedSecret = await X25519.sharedSecret({
 *   privateKey : ownKeyPair.privateKey,
 *   publicKey  : otherPartyKeyPair.publicKey
 * });
 * ```
 */
export declare class X25519 {
    /**
     * Generates a key pair for X25519 (private and public key).
     *
     * @returns A Promise that resolves to a BytesKeyPair object.
     */
    static generateKeyPair(): Promise<BytesKeyPair>;
    /**
     * Computes a public key given a private key.
     *
     * @param options - The options for the public key computation operation.
     * @param options.privateKey - The private key used to compute the public key.
     * @returns A Promise that resolves to the computed public key as a Uint8Array.
     */
    static getPublicKey(options: {
        privateKey: Uint8Array;
    }): Promise<Uint8Array>;
    /**
     * Generates a RFC6090 ECDH shared secret given the private key of one party
     * and the public key of another party.
     *
     * @param options - The options for the shared secret computation operation.
     * @param options.privateKey - The private key of one party.
     * @param options.publicKey - The public key of the other party.
     * @returns A Promise that resolves to the computed shared secret as a Uint8Array.
     */
    static sharedSecret(options: {
        privateKey: Uint8Array;
        publicKey: Uint8Array;
    }): Promise<Uint8Array>;
    /**
     * Note that this method is currently unimplemented because the @noble/curves
     * library does not yet provide a mechanism for checking whether a point
     * belongs to the Curve25519. Therefore, it currently throws an error whenever
     * it is called.
     *
     * @param options - The options for the key validation operation.
     * @param options.key - The key to validate.
     * @throws {Error} If the method is called because it is not yet implemented.
     * @returns A Promise that resolves to void.
     */
    static validatePublicKey(_options: {
        key: Uint8Array;
    }): Promise<void>;
}
//# sourceMappingURL=x25519.d.ts.map