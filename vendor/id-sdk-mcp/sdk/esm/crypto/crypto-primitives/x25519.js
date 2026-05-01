var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { x25519 } from '@noble/curves/ed25519';
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
export class X25519 {
    /**
     * Generates a key pair for X25519 (private and public key).
     *
     * @returns A Promise that resolves to a BytesKeyPair object.
     */
    static generateKeyPair() {
        return __awaiter(this, void 0, void 0, function* () {
            // Generate the private key and compute its public key.
            const privateKey = x25519.utils.randomPrivateKey();
            const publicKey = x25519.getPublicKey(privateKey);
            const keyPair = {
                privateKey: privateKey,
                publicKey: publicKey
            };
            return keyPair;
        });
    }
    /**
     * Computes a public key given a private key.
     *
     * @param options - The options for the public key computation operation.
     * @param options.privateKey - The private key used to compute the public key.
     * @returns A Promise that resolves to the computed public key as a Uint8Array.
     */
    static getPublicKey(options) {
        return __awaiter(this, void 0, void 0, function* () {
            let { privateKey } = options;
            // Compute public key.
            const publicKey = x25519.getPublicKey(privateKey);
            return publicKey;
        });
    }
    /**
     * Generates a RFC6090 ECDH shared secret given the private key of one party
     * and the public key of another party.
     *
     * @param options - The options for the shared secret computation operation.
     * @param options.privateKey - The private key of one party.
     * @param options.publicKey - The public key of the other party.
     * @returns A Promise that resolves to the computed shared secret as a Uint8Array.
     */
    static sharedSecret(options) {
        return __awaiter(this, void 0, void 0, function* () {
            let { privateKey, publicKey } = options;
            const sharedSecret = x25519.getSharedSecret(privateKey, publicKey);
            return sharedSecret;
        });
    }
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
    static validatePublicKey(_options) {
        return __awaiter(this, void 0, void 0, function* () {
            // TODO: add once/if @noble/curves library implements checking
            // proper points on the Montgomery curve.
            throw new Error(`Not implemented: 'validatePublicKey()'`);
        });
    }
}
//# sourceMappingURL=x25519.js.map