"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AppDataVault = void 0;
const index_js_1 = require("../dids/index.js");
const hkdf_1 = require("@noble/hashes/hkdf");
const sha256_1 = require("@noble/hashes/sha256");
const index_js_2 = require("../common/index.js");
const index_js_3 = require("../crypto/index.js");
class AppDataVault {
    constructor(options) {
        var _a, _b;
        this._vaultUnlockKey = new Uint8Array();
        this._keyDerivationWorkFactor = (_a = options === null || options === void 0 ? void 0 : options.keyDerivationWorkFactor) !== null && _a !== void 0 ? _a : 650000;
        this._store = (_b = options === null || options === void 0 ? void 0 : options.store) !== null && _b !== void 0 ? _b : new index_js_2.MemoryStore();
    }
    async backup(_options) {
        throw new Error('Not implemented');
    }
    async changePassphrase(_options) {
        throw new Error('Not implemented');
    }
    async generateVaultUnlockKey(options) {
        const { passphrase, salt } = options;
        /** The salt value derived in Step 3 and the passphrase entered by the
         * end-user are inputs to the PBKDF2 algorithm to derive a 32-byte secret
         * key that will be referred to as the Vault Unlock Key (VUK). */
        const vaultUnlockKey = await index_js_3.Pbkdf2.deriveKey({
            hash: 'SHA-512',
            iterations: this._keyDerivationWorkFactor,
            length: 256,
            password: index_js_2.Convert.string(passphrase).toUint8Array(),
            salt: salt
        });
        return vaultUnlockKey;
    }
    async getDid() {
        // Get the Vault Key Set JWE from the data store.
        const vaultKeySet = await this._store.get('vaultKeySet');
        // Decode the Base64 URL encoded JWE protected header.
        let [protectedHeaderB64U] = vaultKeySet.split('.');
        const protectedHeader = index_js_2.Convert.base64Url(protectedHeaderB64U).toObject();
        // Extract the public key in JWK format.
        const publicKeyJwk = protectedHeader.wrappedKey;
        // Expand the public key to a did:key identifier.
        const keySet = { verificationMethodKeys: [{ publicKeyJwk, relationships: ['authentication'] }] };
        const { did } = await index_js_1.DidKeyMethod.create({ keySet });
        return did;
    }
    async getPublicKey() {
        // Get the Vault Key Set JWE from the data store.
        const vaultKeySet = await this._store.get('vaultKeySet');
        // Decode the Base64 URL encoded JWE protected header.
        let [protectedHeaderB64U] = vaultKeySet.split('.');
        const protectedHeader = index_js_2.Convert.base64Url(protectedHeaderB64U).toObject();
        // Convert the public key in JWK format to crypto key.
        const publicKeyJwk = protectedHeader.wrappedKey;
        const cryptoKey = await index_js_3.Jose.jwkToCryptoKey({ key: publicKeyJwk });
        return cryptoKey;
    }
    async getPrivateKey() {
        // Get the Vault Key Set JWE from the data store.
        const vaultKeySet = await this._store.get('vaultKeySet');
        // Decode the Base64 URL encoded JWE content.
        let [protectedHeaderB64U, encryptedKeyB64U, nonceB64U, _, tagB64U] = vaultKeySet.split('.');
        const protectedHeader = index_js_2.Convert.base64Url(protectedHeaderB64U).toObject();
        const encryptedKey = index_js_2.Convert.base64Url(encryptedKeyB64U).toUint8Array();
        const nonce = index_js_2.Convert.base64Url(nonceB64U).toUint8Array();
        const tag = index_js_2.Convert.base64Url(tagB64U).toUint8Array();
        // Decrypt the Identity Agent's private key material.
        const privateKeyMaterial = await index_js_3.XChaCha20Poly1305.decrypt({
            additionalData: index_js_2.Convert.object(protectedHeader).toUint8Array(),
            data: encryptedKey,
            key: this._vaultUnlockKey,
            nonce: nonce,
            tag: tag
        });
        // Get the public key.
        const publicKey = await this.getPublicKey();
        // Create a private crypto key based off the parameters of the public key.
        const privateKey = new index_js_3.CryptoKey(publicKey.algorithm, publicKey.extractable, privateKeyMaterial, 'private', ['sign']);
        return privateKey;
    }
    async getStatus() {
        try {
            const appDataStatus = await this._store.get('appDataStatus');
            return JSON.parse(appDataStatus);
        }
        catch (error) {
            return {
                initialized: false,
                lastBackup: undefined,
                lastRestore: undefined
            };
        }
    }
    async initialize(options) {
        const { keyPair, passphrase } = options;
        const appDataStatus = await this.getStatus();
        // Throw if the data vault was previously initialized.
        if (appDataStatus.initialized === true) {
            throw new Error(`Operation 'initialize' failed. Data vault already initialized.`);
        }
        /** A non-secret static info value is combined with the Identity Agent's
         * public key as input to a Hash-based Key Derivation Function (HKDF)
         * to derive a new 32-byte salt. */
        const publicKey = keyPair.publicKey.material;
        const saltInput = (0, hkdf_1.hkdf)(sha256_1.sha256, // hash function
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
        const algorithm = index_js_2.Convert.string('PBES2-HS512+XC20PKW').toUint8Array();
        const salt = new Uint8Array([...algorithm, 0x00, ...saltInput]);
        /**
         * Generate a vault unlock key (VUK), which will be used as a
         * key encryption key (KEK) for wrapping the private key */
        // @ts-ignore
        this._vaultUnlockKey = await this.generateVaultUnlockKey({ passphrase, salt });
        /** Convert the public crypto key to JWK format to store within the JWE. */
        const wrappedKey = await index_js_3.Jose.cryptoKeyToJwk({ key: keyPair.publicKey });
        /** Construct the JWE header. */
        const protectedHeader = {
            alg: 'PBES2-HS512+XC20PKW',
            crit: ['wrappedKey'],
            enc: 'XC20P',
            p2c: this._keyDerivationWorkFactor,
            p2s: index_js_2.Convert.uint8Array(salt).toBase64Url(),
            wrappedKey: wrappedKey
        };
        /** 6. Encrypt the Identity Agent's private key with the derived VUK
         *  using XChaCha20-Poly1305 */
        const nonce = index_js_3.utils.randomBytes(24);
        const privateKey = keyPair.privateKey.material;
        const { ciphertext: privateKeyCiphertext, tag: privateKeyTag } = await index_js_3.XChaCha20Poly1305.encrypt({
            additionalData: index_js_2.Convert.object(protectedHeader).toUint8Array(),
            data: privateKey,
            key: this._vaultUnlockKey,
            nonce: nonce
        });
        /** 7. Serialize the Identity Agent's vault key set to a compact JWE, which
         * includes the VUK salt and encrypted VUK (nonce, tag, and ciphertext). */
        const vaultKeySet = index_js_2.Convert.object(protectedHeader).toBase64Url() + '.' +
            index_js_2.Convert.uint8Array(privateKeyCiphertext).toBase64Url() + '.' +
            index_js_2.Convert.uint8Array(nonce).toBase64Url() + '.' +
            index_js_2.Convert.string('unused').toBase64Url() + '.' +
            index_js_2.Convert.uint8Array(privateKeyTag).toBase64Url();
        /** Store the vault key set in the AppDataStore. */
        await this._store.set('vaultKeySet', vaultKeySet);
        /** Set the vault to initialized. */
        appDataStatus.initialized = true;
        await this.setStatus(appDataStatus);
    }
    async lock() {
        this._vaultUnlockKey.fill(0);
        this._vaultUnlockKey = new Uint8Array();
    }
    async restore(_options) {
        throw new Error('Not implemented');
    }
    async setStatus(options) {
        var _a, _b, _c;
        // Get the current status values from the store, if any.
        const appDataStatus = await this.getStatus();
        // Update the status properties with new values specified, if any.
        appDataStatus.initialized = (_a = options.initialized) !== null && _a !== void 0 ? _a : appDataStatus.initialized;
        appDataStatus.lastBackup = (_b = options.lastBackup) !== null && _b !== void 0 ? _b : appDataStatus.lastBackup;
        appDataStatus.lastRestore = (_c = options.lastRestore) !== null && _c !== void 0 ? _c : appDataStatus.lastRestore;
        // Write the changes to the store.
        await this._store.set('appDataStatus', JSON.stringify(appDataStatus));
        return true;
    }
    async unlock(options) {
        const { passphrase } = options;
        // Get the vault key set from the store.
        const vaultKeySet = await this._store.get('vaultKeySet');
        // Decode the protected header.
        let [protectedHeaderString] = vaultKeySet.split('.');
        const protectedHeader = index_js_2.Convert.base64Url(protectedHeaderString).toObject();
        // Derive the Vault Unlock Key (VUK).
        if (protectedHeader.p2s !== undefined) {
            const salt = index_js_2.Convert.base64Url(protectedHeader.p2s).toUint8Array();
            // @ts-ignore
            this._vaultUnlockKey = await this.generateVaultUnlockKey({ passphrase, salt });
        }
        return true;
    }
}
exports.AppDataVault = AppDataVault;
//# sourceMappingURL=app-data-store.js.map