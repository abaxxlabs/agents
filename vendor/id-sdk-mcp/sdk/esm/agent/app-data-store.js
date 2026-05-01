var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { DidKeyMethod } from '../dids/index.js';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { Convert, MemoryStore } from '../common/index.js';
import { CryptoKey, Jose, Pbkdf2, utils as cryptoUtils, XChaCha20Poly1305 } from '../crypto/index.js';
export class AppDataVault {
    constructor(options) {
        var _a, _b;
        this._vaultUnlockKey = new Uint8Array();
        this._keyDerivationWorkFactor = (_a = options === null || options === void 0 ? void 0 : options.keyDerivationWorkFactor) !== null && _a !== void 0 ? _a : 650000;
        this._store = (_b = options === null || options === void 0 ? void 0 : options.store) !== null && _b !== void 0 ? _b : new MemoryStore();
    }
    backup(_options) {
        return __awaiter(this, void 0, void 0, function* () {
            throw new Error('Not implemented');
        });
    }
    changePassphrase(_options) {
        return __awaiter(this, void 0, void 0, function* () {
            throw new Error('Not implemented');
        });
    }
    generateVaultUnlockKey(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const { passphrase, salt } = options;
            /** The salt value derived in Step 3 and the passphrase entered by the
             * end-user are inputs to the PBKDF2 algorithm to derive a 32-byte secret
             * key that will be referred to as the Vault Unlock Key (VUK). */
            const vaultUnlockKey = yield Pbkdf2.deriveKey({
                hash: 'SHA-512',
                iterations: this._keyDerivationWorkFactor,
                length: 256,
                password: Convert.string(passphrase).toUint8Array(),
                salt: salt
            });
            return vaultUnlockKey;
        });
    }
    getDid() {
        return __awaiter(this, void 0, void 0, function* () {
            // Get the Vault Key Set JWE from the data store.
            const vaultKeySet = yield this._store.get('vaultKeySet');
            // Decode the Base64 URL encoded JWE protected header.
            let [protectedHeaderB64U] = vaultKeySet.split('.');
            const protectedHeader = Convert.base64Url(protectedHeaderB64U).toObject();
            // Extract the public key in JWK format.
            const publicKeyJwk = protectedHeader.wrappedKey;
            // Expand the public key to a did:key identifier.
            const keySet = { verificationMethodKeys: [{ publicKeyJwk, relationships: ['authentication'] }] };
            const { did } = yield DidKeyMethod.create({ keySet });
            return did;
        });
    }
    getPublicKey() {
        return __awaiter(this, void 0, void 0, function* () {
            // Get the Vault Key Set JWE from the data store.
            const vaultKeySet = yield this._store.get('vaultKeySet');
            // Decode the Base64 URL encoded JWE protected header.
            let [protectedHeaderB64U] = vaultKeySet.split('.');
            const protectedHeader = Convert.base64Url(protectedHeaderB64U).toObject();
            // Convert the public key in JWK format to crypto key.
            const publicKeyJwk = protectedHeader.wrappedKey;
            const cryptoKey = yield Jose.jwkToCryptoKey({ key: publicKeyJwk });
            return cryptoKey;
        });
    }
    getPrivateKey() {
        return __awaiter(this, void 0, void 0, function* () {
            // Get the Vault Key Set JWE from the data store.
            const vaultKeySet = yield this._store.get('vaultKeySet');
            // Decode the Base64 URL encoded JWE content.
            let [protectedHeaderB64U, encryptedKeyB64U, nonceB64U, _, tagB64U] = vaultKeySet.split('.');
            const protectedHeader = Convert.base64Url(protectedHeaderB64U).toObject();
            const encryptedKey = Convert.base64Url(encryptedKeyB64U).toUint8Array();
            const nonce = Convert.base64Url(nonceB64U).toUint8Array();
            const tag = Convert.base64Url(tagB64U).toUint8Array();
            // Decrypt the Identity Agent's private key material.
            const privateKeyMaterial = yield XChaCha20Poly1305.decrypt({
                additionalData: Convert.object(protectedHeader).toUint8Array(),
                data: encryptedKey,
                key: this._vaultUnlockKey,
                nonce: nonce,
                tag: tag
            });
            // Get the public key.
            const publicKey = yield this.getPublicKey();
            // Create a private crypto key based off the parameters of the public key.
            const privateKey = new CryptoKey(publicKey.algorithm, publicKey.extractable, privateKeyMaterial, 'private', ['sign']);
            return privateKey;
        });
    }
    getStatus() {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const appDataStatus = yield this._store.get('appDataStatus');
                return JSON.parse(appDataStatus);
            }
            catch (error) {
                return {
                    initialized: false,
                    lastBackup: undefined,
                    lastRestore: undefined
                };
            }
        });
    }
    initialize(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const { keyPair, passphrase } = options;
            const appDataStatus = yield this.getStatus();
            // Throw if the data vault was previously initialized.
            if (appDataStatus.initialized === true) {
                throw new Error(`Operation 'initialize' failed. Data vault already initialized.`);
            }
            /** A non-secret static info value is combined with the Identity Agent's
             * public key as input to a Hash-based Key Derivation Function (HKDF)
             * to derive a new 32-byte salt. */
            const publicKey = keyPair.publicKey.material;
            const saltInput = hkdf(sha256, // hash function
            publicKey, // input keying material
            undefined, // no salt because public key is already random
            'vault_unlock_salt', // non-secret application specific information
            32 // derived key length, in bytes
            );
            /**
             * Per RFC 7518, the salt value used with PBES2 should be of the format
             * (UTF8(Alg) || 0x00 || Salt Input), where Alg is the "alg" (algorithm)
             * Header Parameter value. This reduces the potential for a precomputed
             * dictionary attack (also known as a rainbow table attack).
             * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-4.8.1.1 | RFC 7518, Section 4.8.1.1}
             */
            const algorithm = Convert.string('PBES2-HS512+XC20PKW').toUint8Array();
            const salt = new Uint8Array([...algorithm, 0x00, ...saltInput]);
            /**
             * Generate a vault unlock key (VUK), which will be used as a
             * key encryption key (KEK) for wrapping the private key */
            // @ts-ignore
            this._vaultUnlockKey = yield this.generateVaultUnlockKey({ passphrase, salt });
            /** Convert the public crypto key to JWK format to store within the JWE. */
            const wrappedKey = yield Jose.cryptoKeyToJwk({ key: keyPair.publicKey });
            /** Construct the JWE header. */
            const protectedHeader = {
                alg: 'PBES2-HS512+XC20PKW',
                crit: ['wrappedKey'],
                enc: 'XC20P',
                p2c: this._keyDerivationWorkFactor,
                p2s: Convert.uint8Array(salt).toBase64Url(),
                wrappedKey: wrappedKey
            };
            /** 6. Encrypt the Identity Agent's private key with the derived VUK
             *  using XChaCha20-Poly1305 */
            const nonce = cryptoUtils.randomBytes(24);
            const privateKey = keyPair.privateKey.material;
            const { ciphertext: privateKeyCiphertext, tag: privateKeyTag } = yield XChaCha20Poly1305.encrypt({
                additionalData: Convert.object(protectedHeader).toUint8Array(),
                data: privateKey,
                key: this._vaultUnlockKey,
                nonce: nonce
            });
            /** 7. Serialize the Identity Agent's vault key set to a compact JWE, which
             * includes the VUK salt and encrypted VUK (nonce, tag, and ciphertext). */
            const vaultKeySet = Convert.object(protectedHeader).toBase64Url() + '.' +
                Convert.uint8Array(privateKeyCiphertext).toBase64Url() + '.' +
                Convert.uint8Array(nonce).toBase64Url() + '.' +
                Convert.string('unused').toBase64Url() + '.' +
                Convert.uint8Array(privateKeyTag).toBase64Url();
            /** Store the vault key set in the AppDataStore. */
            yield this._store.set('vaultKeySet', vaultKeySet);
            /** Set the vault to initialized. */
            appDataStatus.initialized = true;
            yield this.setStatus(appDataStatus);
        });
    }
    lock() {
        return __awaiter(this, void 0, void 0, function* () {
            this._vaultUnlockKey.fill(0);
            this._vaultUnlockKey = new Uint8Array();
        });
    }
    restore(_options) {
        return __awaiter(this, void 0, void 0, function* () {
            throw new Error('Not implemented');
        });
    }
    setStatus(options) {
        var _a, _b, _c;
        return __awaiter(this, void 0, void 0, function* () {
            // Get the current status values from the store, if any.
            const appDataStatus = yield this.getStatus();
            // Update the status properties with new values specified, if any.
            appDataStatus.initialized = (_a = options.initialized) !== null && _a !== void 0 ? _a : appDataStatus.initialized;
            appDataStatus.lastBackup = (_b = options.lastBackup) !== null && _b !== void 0 ? _b : appDataStatus.lastBackup;
            appDataStatus.lastRestore = (_c = options.lastRestore) !== null && _c !== void 0 ? _c : appDataStatus.lastRestore;
            // Write the changes to the store.
            yield this._store.set('appDataStatus', JSON.stringify(appDataStatus));
            return true;
        });
    }
    unlock(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const { passphrase } = options;
            // Get the vault key set from the store.
            const vaultKeySet = yield this._store.get('vaultKeySet');
            // Decode the protected header.
            let [protectedHeaderString] = vaultKeySet.split('.');
            const protectedHeader = Convert.base64Url(protectedHeaderString).toObject();
            // Derive the Vault Unlock Key (VUK).
            if (protectedHeader.p2s !== undefined) {
                const salt = Convert.base64Url(protectedHeader.p2s).toUint8Array();
                // @ts-ignore
                this._vaultUnlockKey = yield this.generateVaultUnlockKey({ passphrase, salt });
            }
            return true;
        });
    }
}
//# sourceMappingURL=app-data-store.js.map