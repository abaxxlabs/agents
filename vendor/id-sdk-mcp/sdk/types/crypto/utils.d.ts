import type { IDCrypto } from './types/iddwn-crypto.js';
import type { BytesKeyPair } from './types/crypto-key.js';
/**
 * Checks whether the properties object provided contains the specified property.
 *
 * @param property Property key to check for.
 * @param properties Properties object to check within.
 * @returns void
 * @throws {SyntaxError} If the property is not a key in the properties object.
 */
export declare function checkRequiredProperty(options: {
    property: string;
    inObject: object;
}): void;
/**
 * Checks whether the property specified is a member of the list of valid properties.
 *
 * @param property Property key to check for.
 * @param allowedProperties Properties Array, Map, or Set to check within.
 * @returns void
 * @throws {SyntaxError} If the property is not a member of the allowedProperties Array, Map, or Set.
 */
export declare function checkValidProperty(options: {
    property: string;
    allowedProperties: Array<string> | Map<string, unknown> | Set<string>;
}): void;
/**
 * Type guard function to check if the given key is a raw key pair
 * of Uint8Array typed arrays.
 *
 * @param key The key to check.
 * @returns True if the key is a pair of Uint8Array typed arrays, false otherwise.
 */
export declare function isBytesKeyPair(key: BytesKeyPair | undefined): key is BytesKeyPair;
/**
 * Type guard function to check if the given key is a
 * IDCrypto.CryptoKeyPair.
 *
 * @param key The key to check.
 * @returns True if the key is a CryptoKeyPair, false otherwise.
 */
export declare function isCryptoKeyPair(key: IDCrypto.CryptoKey | IDCrypto.CryptoKeyPair): key is IDCrypto.CryptoKeyPair;
export declare function keyToMultibaseId(options: {
    key: Uint8Array;
    multicodecCode?: number;
    multicodecName?: string;
}): string;
/**
 * Checks if the Web Crypto API is supported in the current runtime environment.
 *
 * The function uses `globalThis` to provide a universal reference to the global
 * scope, regardless of the environment. `globalThis` is a standard feature introduced
 * in ECMAScript 2020 that is agnostic to the underlying JavaScript environment, making
 * the code portable across browser, Node.js, and Web Workers environments.
 *
 * In a web browser, `globalThis` is equivalent to the `window` object. In Node.js, it
 * is equivalent to the `global` object, and in Web Workers, it corresponds to `self`.
 *
 * This method checks for the `crypto` object and its `subtle` property on the global scope
 * to determine the availability of the Web Crypto API. If both are present, the API is
 * supported; otherwise, it is not.
 *
 * @returns A boolean indicating whether the Web Crypto API is supported in the current environment.
 *
 * Example usage:
 *
 * ```ts
 * if (isWebCryptoSupported()) {
 *   console.log('Crypto operations can be performed');
 * } else {
 *   console.log('Crypto operations are not supported in this environment');
 * }
 * ```
 */
export declare function isWebCryptoSupported(): boolean;
export declare function multibaseIdToKey(options: {
    multibaseKeyId: string;
}): {
    key: Uint8Array;
    multicodecCode: number;
    multicodecName: string;
};
/**
 * Generates secure pseudorandom values of the specified length using
 * `crypto.getRandomValues`, which defers to the operating system.
 *
 * This function is a wrapper around `randomBytes` from the '@noble/hashes'
 * package. It's designed to be cryptographically strong, suitable for
 * generating keys, initialization vectors, and other random values.
 *
 * @param bytesLength - The number of bytes to generate.
 * @returns A Uint8Array containing the generated random bytes.
 *
 * @example
 * const bytes = randomBytes(32); // Generates 32 random bytes
 *
 * @see {@link https://www.npmjs.com/package/@noble/hashes | @noble/hashes on NPM}
 * for more information about the underlying implementation.
 */
export declare function randomBytes(bytesLength: number): Uint8Array;
/**
 * Generates a UUID (Universally Unique Identifier) using a
 * cryptographically strong random number generator following
 * the version 4 format, as specified in RFC 4122.
 *
 * A version 4 UUID is a randomly generated UUID. The 13th character
 * is set to '4' to denote version 4, and the 17th character is one
 * of '8', '9', 'A', or 'B' to comply with the variant 1 format of
 * UUIDs (the high bits are set to '10').
 *
 * The UUID is a 36 character string, including hyphens, and looks like this:
 * xxxxxxxx-xxxx-4xxx-axxx-xxxxxxxxxxxx
 *
 * Note that while UUIDs are not guaranteed to be unique, they are
 * practically unique" given the large number of possible UUIDs and
 * the randomness of generation.
 *
 * After generating the UUID, the function securely wipes the memory
 * areas used to hold temporary values to prevent any possibility of
 * the random values being unintentionally leaked or retained in memory.
 *
 * @returns A UUID string in version 4 format.
 */
export declare function randomUuid(): string;
//# sourceMappingURL=utils.d.ts.map