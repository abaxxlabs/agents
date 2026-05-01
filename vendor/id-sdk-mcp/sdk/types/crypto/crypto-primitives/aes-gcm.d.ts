/**
 * The `AesGcm` class provides an interface for AES-GCM
 * (Advanced Encryption Standard - Galois/Counter Mode) encryption and
 * decryption operations. The class uses the Web Crypto API for
 * cryptographic operations.
 *
 * All methods of this class are asynchronous and return Promises. They all
 * use the Uint8Array type for keys and data, providing a consistent
 * interface for working with binary data.
 *
 * Example usage:
 *
 * ```ts
 * const key = await AesGcm.generateKey({ length: 128 });
 * const iv = new Uint8Array(12); // generate a 12-byte initialization vector
 * const message = new TextEncoder().encode('Hello, world!');
 * const ciphertext = await AesGcm.encrypt({
 *   data: message,
 *   iv,
 *   key,
 *   tagLength: 128
 * });
 * const plaintext = await AesGcm.decrypt({
 *   data: ciphertext,
 *   iv,
 *   key,
 *   tagLength: 128
 * });
 * console.log(new TextDecoder().decode(plaintext)); // 'Hello, world!'
 * ```
 */
export declare class AesGcm {
    /**
     * Decrypts the provided data using AES-GCM.
     *
     * @param options - The options for the decryption operation.
     * @param options.additionalData - Data that will be authenticated along with the encrypted data.
     * @param options.data - The data to decrypt.
     * @param options.iv - A unique initialization vector.
     * @param options.key - The key to use for decryption.
     * @param options.tagLength - This size of the authentication tag generated in bits.
     * @returns A Promise that resolves to the decrypted data as a Uint8Array.
     */
    static decrypt(options: {
        additionalData?: Uint8Array;
        data: Uint8Array;
        iv: Uint8Array;
        key: Uint8Array;
        tagLength?: number;
    }): Promise<Uint8Array>;
    /**
     * Encrypts the provided data using AES-GCM.
     *
     * @param options - The options for the encryption operation.
     * @param options.additionalData - Data that will be authenticated along with the encrypted data.
     * @param options.data - The data to decrypt.
     * @param options.iv - A unique initialization vector.
     * @param options.key - The key to use for decryption.
     * @param options.tagLength - This size of the authentication tag generated in bits.
     * @returns A Promise that resolves to the encrypted data as a Uint8Array.
     */
    static encrypt(options: {
        additionalData?: Uint8Array;
        data: Uint8Array;
        iv: Uint8Array;
        key: Uint8Array;
        tagLength?: number;
    }): Promise<Uint8Array>;
    /**
     * Generates an AES key of a given length.
     *
     * @param length - The length of the key in bits.
     * @returns A Promise that resolves to the generated key as a Uint8Array.
     */
    static generateKey(options: {
        length: number;
    }): Promise<Uint8Array>;
    /**
     * A private method to import a raw key for use with the Web Crypto API.
     *
     * @param key - The raw key material.
     * @returns A Promise that resolves to a CryptoKey.
     */
    private static importKey;
}
//# sourceMappingURL=aes-gcm.d.ts.map