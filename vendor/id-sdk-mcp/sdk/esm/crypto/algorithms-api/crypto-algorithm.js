import { InvalidAccessError, NotSupportedError } from './errors.js';
export class CryptoAlgorithm {
    checkAlgorithmName(options) {
        const { algorithmName } = options;
        if (algorithmName === undefined) {
            throw new TypeError(`Required parameter missing: 'algorithmName'`);
        }
        if (algorithmName !== this.name) {
            throw new NotSupportedError(`Algorithm not supported: '${algorithmName}'`);
        }
    }
    checkCryptoKey(options) {
        const { key } = options;
        if (!('algorithm' in key && 'extractable' in key && 'type' in key && 'usages' in key)) {
            throw new TypeError('Object is not a CryptoKey');
        }
    }
    checkKeyAlgorithm(options) {
        const { keyAlgorithmName } = options;
        if (keyAlgorithmName === undefined) {
            throw new TypeError(`Required parameter missing: 'keyAlgorithmName'`);
        }
        if (keyAlgorithmName && keyAlgorithmName !== this.name) {
            throw new InvalidAccessError(`Algorithm '${this.name}' does not match the provided '${keyAlgorithmName}' key.`);
        }
    }
    checkKeyType(options) {
        const { keyType, allowedKeyType } = options;
        if (keyType === undefined || allowedKeyType === undefined) {
            throw new TypeError(`One or more required parameters missing: 'keyType, allowedKeyType'`);
        }
        if (keyType && keyType !== allowedKeyType) {
            throw new InvalidAccessError(`Requested operation is not valid for the provided '${keyType}' key.`);
        }
    }
    checkKeyUsages(options) {
        const { keyUsages, allowedKeyUsages } = options;
        if (!(keyUsages && keyUsages.length > 0)) {
            throw new TypeError(`Required parameter missing or empty: 'keyUsages'`);
        }
        const allowedUsages = (Array.isArray(allowedKeyUsages)) ? allowedKeyUsages : [...allowedKeyUsages.privateKey, ...allowedKeyUsages.publicKey];
        if (!keyUsages.every(usage => allowedUsages.includes(usage))) {
            throw new InvalidAccessError(`Requested operation(s) '${keyUsages.join(', ')}' is not valid for the provided key.`);
        }
    }
    /**
     * Creates an instance of the class on which it is called.
     *
     * This is a generic factory method that creates an instance of any
     * crypto algorithm that extends this abstract class.
     *
     * @template T The type of the instance to be created.
     * @returns An instance of the class it is called on.
     * @throws {TypeError} If the class it is called on cannot be constructed.
     */
    static create() {
        return new this();
    }
}
//# sourceMappingURL=crypto-algorithm.js.map