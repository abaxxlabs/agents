import type { BytesKeyPair } from '../types/crypto-key.js';
/**
 * The `Ed25519` class provides an interface for generating Ed25519 key pairs,
 * computing public keys from private keys, and signing and verifying messages.
 *
 * The class uses the '@noble/curves' package for the cryptographic operations.
 *
 * The methods of this class are all asynchronous and return Promises. They all use
 * the Uint8Array type for keys, signatures, and data, providing a consistent
 * interface for working with binary data.
 *
 * Example usage:
 *
 * ```ts
 * const keyPair = await Ed25519.generateKeyPair();
 * const message = new TextEncoder().encode('Hello, world!');
 * const signature = await Ed25519.sign({
 *   key: keyPair.privateKey,
 *   data: message
 * });
 * const isValid = await Ed25519.verify({
 *   key: keyPair.publicKey,
 *   signature,
 *   data: message
 * });
 * console.log(isValid); // true
 * ```
 */
export declare class Ed25519 {
    /**
     * Converts an Ed25519 private key to its X25519 counterpart.
     *
     * Similar to the public key conversion, this method aids in transitioning
     * from signing to encryption operations. By converting an Ed25519 private
     * key to X25519 format, one can use the same key pair for both digital
     * signatures and key exchange operations.
     *
     * @param options - The options for the conversion.
     * @param options.privateKey - The Ed25519 private key to convert, represented as a Uint8Array.
     * @returns A Promise that resolves to the X25519 private key as a Uint8Array.
     */
    static convertPrivateKeyToX25519(options: {
        privateKey: Uint8Array;
    }): Promise<Uint8Array>;
    /**
   * Converts an Ed25519 public key to its X25519 counterpart.
   *
   * This method is useful when transitioning from signing to encryption
   * operations, as Ed25519 and X25519 keys share the same mathematical
   * foundation but serve different purposes. Ed25519 keys are used for
   * digital signatures, while X25519 keys are used for key exchange in
   * encryption protocols like Diffie-Hellman.
   *
   * @param options - The options for the conversion.
   * @param options.publicKey - The Ed25519 public key to convert, represented as a Uint8Array.
   * @returns A Promise that resolves to the X25519 public key as a Uint8Array.
   */
    static convertPublicKeyToX25519(options: {
        publicKey: Uint8Array;
    }): Promise<Uint8Array>;
    /**
     * Generates an Ed25519 key pair.
     *
     * @returns A Promise that resolves to an object containing the private and public keys as Uint8Array.
     */
    static generateKeyPair(): Promise<BytesKeyPair>;
    /**
     * Computes the public key from a given private key.
     *
     * @param options - The options for the public key computation.
     * @param options.privateKey - The 32-byte private key from which to compute the public key.
     * @returns A Promise that resolves to the computed 32-byte public key as a Uint8Array.
     */
    static getPublicKey(options: {
        privateKey: Uint8Array;
    }): Promise<Uint8Array>;
    /**
     * Generates a RFC8032 EdDSA signature of given data with a given private key.
     *
     * @param options - The options for the signing operation.
     * @param options.key - The private key to use for signing.
     * @param options.data - The data to sign.
     * @returns A Promise that resolves to the signature as a Uint8Array.
     */
    static sign(options: {
        data: Uint8Array;
        key: Uint8Array;
    }): Promise<Uint8Array>;
    /**
     * Validates a given public key to ensure that it corresponds to a
     * valid point on the Ed25519 elliptic curve.
     *
     * This method decodes the Edwards points from the key bytes and
     * asserts their validity on the curve. If the points are not valid,
     * the method returns false. If the points are valid, the method
     * returns true.
     *
     * Note: This method does not check whether the key corresponds to a
     * known or authorized entity, or whether it has been compromised.
     * It only checks the mathematical validity of the key.
     *
     * @param options - The options for the key validation.
     * @param options.key - The key to validate, represented as a Uint8Array.
     * @returns A Promise that resolves to a boolean indicating whether the key
     *          corresponds to a valid point on the Edwards curve.
     */
    static validatePublicKey(options: {
        key: Uint8Array;
    }): Promise<boolean>;
    /**
     * Verifies a RFC8032 EdDSA signature of given data with a given public key.
     *
     * @param options - The options for the verification operation.
     * @param options.key - The public key to use for verification.
     * @param options.signature - The signature to verify.
     * @param options.data - The data that was signed.
     * @returns A Promise that resolves to a boolean indicating whether the signature is valid.
     */
    static verify(options: {
        data: Uint8Array;
        key: Uint8Array;
        signature: Uint8Array;
    }): Promise<boolean>;
}
//# sourceMappingURL=ed25519.d.ts.map