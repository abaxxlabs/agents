var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { ed25519, edwardsToMontgomeryPub, edwardsToMontgomeryPriv } from '@noble/curves/ed25519';
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
export class Ed25519 {
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
    static convertPrivateKeyToX25519(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const { privateKey } = options;
            // Converts Ed25519 private key to X25519 private key.
            const montgomeryPrivateKey = edwardsToMontgomeryPriv(privateKey);
            return montgomeryPrivateKey;
        });
    }
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
    static convertPublicKeyToX25519(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const { publicKey } = options;
            // Verify Edwards public key is valid.
            const isValid = yield Ed25519.validatePublicKey({ key: publicKey });
            if (!isValid) {
                throw new Error('Ed25519: Invalid public key.');
            }
            // Converts Ed25519 public key to X25519 public key.
            const montgomeryPublicKey = edwardsToMontgomeryPub(publicKey);
            return montgomeryPublicKey;
        });
    }
    /**
     * Generates an Ed25519 key pair.
     *
     * @returns A Promise that resolves to an object containing the private and public keys as Uint8Array.
     */
    static generateKeyPair() {
        return __awaiter(this, void 0, void 0, function* () {
            // Generate the private key and compute its public key.
            const privateKey = ed25519.utils.randomPrivateKey();
            const publicKey = ed25519.getPublicKey(privateKey);
            const keyPair = {
                privateKey: privateKey,
                publicKey: publicKey
            };
            return keyPair;
        });
    }
    /**
     * Computes the public key from a given private key.
     *
     * @param options - The options for the public key computation.
     * @param options.privateKey - The 32-byte private key from which to compute the public key.
     * @returns A Promise that resolves to the computed 32-byte public key as a Uint8Array.
     */
    static getPublicKey(options) {
        return __awaiter(this, void 0, void 0, function* () {
            let { privateKey } = options;
            // Compute public key.
            const publicKey = ed25519.getPublicKey(privateKey);
            return publicKey;
        });
    }
    /**
     * Generates a RFC8032 EdDSA signature of given data with a given private key.
     *
     * @param options - The options for the signing operation.
     * @param options.key - The private key to use for signing.
     * @param options.data - The data to sign.
     * @returns A Promise that resolves to the signature as a Uint8Array.
     */
    static sign(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const { key, data } = options;
            // Signature operation.
            const signature = ed25519.sign(data, key);
            return signature;
        });
    }
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
    static validatePublicKey(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const { key } = options;
            try {
                // Decode Edwards points from key bytes.
                const point = ed25519.ExtendedPoint.fromHex(key);
                // Check if points are on the Twisted Edwards curve.
                point.assertValidity();
            }
            catch (error) {
                return false;
            }
            return true;
        });
    }
    /**
     * Verifies a RFC8032 EdDSA signature of given data with a given public key.
     *
     * @param options - The options for the verification operation.
     * @param options.key - The public key to use for verification.
     * @param options.signature - The signature to verify.
     * @param options.data - The data that was signed.
     * @returns A Promise that resolves to a boolean indicating whether the signature is valid.
     */
    static verify(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const { key, signature, data } = options;
            // Verify operation.
            const isValid = ed25519.verify(signature, data, key);
            return isValid;
        });
    }
}
//# sourceMappingURL=ed25519.js.map