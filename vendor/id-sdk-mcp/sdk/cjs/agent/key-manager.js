"use strict";
var __rest = (this && this.__rest) || function (s, e) {
    var t = {};
    for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p) && e.indexOf(p) < 0)
        t[p] = s[p];
    if (s != null && typeof Object.getOwnPropertySymbols === "function")
        for (var i = 0, p = Object.getOwnPropertySymbols(s); i < p.length; i++) {
            if (e.indexOf(p[i]) < 0 && Object.prototype.propertyIsEnumerable.call(s, p[i]))
                t[p[i]] = s[p[i]];
        }
    return t;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.KeyManager = void 0;
const kms_local_js_1 = require("./kms-local.js");
const utils_js_1 = require("./utils.js");
const store_managed_key_js_1 = require("./store-managed-key.js");
/**
 * KeyManager
 *
 * This class orchestrates implementations of {@link KeyManagementSystem},
 * using a ManagedKeyStore to remember the link between a key reference,
 * its metadata, and the respective key management system that provides the
 * actual cryptographic capabilities.
 *
 * The methods of this class are used automatically by other Agent
 * components to perform their required cryptographic operations using
 * the managed keys.
 *
 * @public
 */
class KeyManager {
    constructor(options) {
        let { agent, kms, store } = options !== null && options !== void 0 ? options : {};
        this._agent = agent;
        this._store = store !== null && store !== void 0 ? store : new store_managed_key_js_1.KeyStoreMemory();
        kms !== null && kms !== void 0 ? kms : (kms = this.useMemoryKms());
        this._kms = new Map(Object.entries(kms));
    }
    /**
     * Retrieves the `IDManagedAgent` execution context.
     * If the `agent` instance proprety is undefined, it will throw an error.
     *
     * @returns The `IDManagedAgent` instance that represents the current execution
     * context.
     *
     * @throws Will throw an error if the `agent` instance property is undefined.
     */
    get agent() {
        if (this._agent === undefined) {
            throw new Error('KeyManager: Unable to determine agent execution context.');
        }
        return this._agent;
    }
    set agent(agent) {
        this._agent = agent;
        this._kms.forEach((kms) => {
            kms.agent = agent;
        });
    }
    async decrypt(options) {
        let { keyRef } = options, decryptOptions = __rest(options, ["keyRef"]);
        const key = await this.getKey({ keyRef });
        if (!(0, utils_js_1.isManagedKey)(key)) {
            throw new Error(`Key not found: '${keyRef}'`);
        }
        const kmsName = key.kms;
        const kms = this.getKms(kmsName);
        const keyId = key.id;
        const plaintext = await kms.decrypt(Object.assign({ keyRef: keyId }, decryptOptions));
        return plaintext;
    }
    async deriveBits(options) {
        const { baseKeyRef } = options, deriveBitsOptions = __rest(options, ["baseKeyRef"]);
        const ownKeyPair = await this.getKey({ keyRef: baseKeyRef });
        if (!(0, utils_js_1.isManagedKeyPair)(ownKeyPair)) {
            throw new Error(`Key not found: '${baseKeyRef}'`);
        }
        const kmsName = ownKeyPair.privateKey.kms;
        const kms = this.getKms(kmsName);
        const ownKeyId = ownKeyPair.privateKey.id;
        const sharedSecret = kms.deriveBits(Object.assign({ baseKeyRef: ownKeyId }, deriveBitsOptions));
        return sharedSecret;
    }
    async encrypt(options) {
        let { keyRef } = options, encryptOptions = __rest(options, ["keyRef"]);
        const key = await this.getKey({ keyRef });
        if (!(0, utils_js_1.isManagedKey)(key)) {
            throw new Error(`Key not found: '${keyRef}'`);
        }
        const kmsName = key.kms;
        const kms = this.getKms(kmsName);
        const keyId = key.id;
        const ciphertext = await kms.encrypt(Object.assign({ keyRef: keyId }, encryptOptions));
        return ciphertext;
    }
    async generateKey(options) {
        const { kms: kmsName } = options, generateKeyOptions = __rest(options, ["kms"]);
        const kms = this.getKms(kmsName);
        const keyOrKeyPair = await kms.generateKey(generateKeyOptions);
        // Store the ManagedKey or ManagedKeyPair in KeyManager's key store.
        await this._store.importKey({ key: keyOrKeyPair, agent: this.agent });
        return keyOrKeyPair;
    }
    async getKey({ keyRef }) {
        var _a, _b;
        let keyOrKeyPair;
        // First, check to see if the requested key is the default signing key.
        const defaultSigningKeyId = (_a = this._defaultSigningKey) === null || _a === void 0 ? void 0 : _a.publicKey.id;
        const defaultSigningKeyAlias = (_b = this._defaultSigningKey) === null || _b === void 0 ? void 0 : _b.publicKey.alias;
        if (keyRef === defaultSigningKeyId || keyRef === defaultSigningKeyAlias) {
            return this._defaultSigningKey;
        }
        // Try to get key by ID.
        keyOrKeyPair = await this._store.getKey({ id: keyRef, agent: this.agent });
        if (keyOrKeyPair)
            return keyOrKeyPair;
        // Try to find key by alias.
        keyOrKeyPair = await this._store.findKey({ alias: keyRef, agent: this.agent });
        if (keyOrKeyPair)
            return keyOrKeyPair;
        return undefined;
    }
    async importKey(options) {
        const kmsName = ('privateKey' in options) ? options.privateKey.kms : options.kms;
        const kms = this.getKms(kmsName);
        // Store the ManagedKey or ManagedKeyPair in the given KMS.
        const importedKeyOrKeyPair = await kms.importKey(options);
        // Store the ManagedKey or ManagedKeyPair in KeyManager's key store.
        await this._store.importKey({ key: importedKeyOrKeyPair, agent: this.agent });
        return importedKeyOrKeyPair;
    }
    listKms() {
        return Array.from(this._kms.keys());
    }
    async setDefaultSigningKey({ key }) {
        const kmsName = key.privateKey.kms;
        const kms = this.getKms(kmsName);
        // Store the default signing key pair in an in-memory KMS.
        const importedDefaultSigningKey = await kms.importKey(key);
        // Set the in-memory key to be KeyManager's default signing key.
        this._defaultSigningKey = importedDefaultSigningKey;
    }
    async sign(options) {
        const { keyRef } = options, signOptions = __rest(options, ["keyRef"]);
        const keyPair = await this.getKey({ keyRef });
        if (!(0, utils_js_1.isManagedKeyPair)(keyPair)) {
            throw new Error(`Key not found: '${keyRef}'`);
        }
        const kmsName = keyPair.privateKey.kms;
        const kms = this.getKms(kmsName);
        const keyId = keyPair.privateKey.id;
        const signature = await kms.sign(Object.assign({ keyRef: keyId }, signOptions));
        return signature;
    }
    async updateKey(options) {
        const { keyRef, alias, metadata } = options;
        const keyOrKeyPair = await this.getKey({ keyRef });
        if (!keyOrKeyPair) {
            throw new Error(`Key not found: '${keyRef}'`);
        }
        const { id: keyId, kms: kmsName } = ((0, utils_js_1.isManagedKeyPair)(keyOrKeyPair))
            ? Object.assign({}, keyOrKeyPair.publicKey) : Object.assign({}, keyOrKeyPair);
        // Update the ManagedKey or ManagedKeyPair in the given KMS.
        const kms = this.getKms(kmsName);
        const kmsUpdated = await kms.updateKey(options);
        if (!kmsUpdated)
            return false;
        // Since the KMS was successfully updated, update the KeyManager store.
        return await this._store.updateKey({ id: keyId, alias, metadata, agent: this.agent });
    }
    async verify(options) {
        let { keyRef } = options, verifyOptions = __rest(options, ["keyRef"]);
        const keyPair = await this.getKey({ keyRef });
        if (!(0, utils_js_1.isManagedKeyPair)(keyPair)) {
            throw new Error(`Key not found: '${keyRef}'`);
        }
        const kmsName = keyPair.publicKey.kms;
        const kms = this.getKms(kmsName);
        const keyId = keyPair.publicKey.id;
        const isValid = await kms.verify(Object.assign({ keyRef: keyId }, verifyOptions));
        return isValid;
    }
    getKms(name) {
        // For developer convenience, if a KMS name isn't specified and KeyManager only has
        // one KMS defined, use it.  Otherwise, an exception will be thrown.
        name !== null && name !== void 0 ? name : (name = (this._kms.size === 1) ? this._kms.keys().next().value : '');
        const kms = this._kms.get(name);
        if (!kms) {
            throw Error(`Unknown key management system: '${name}'`);
        }
        return kms;
    }
    useMemoryKms() {
        // Instantiate in-memory store for KMS key metadata and public keys.
        const keyStore = new store_managed_key_js_1.KeyStoreMemory();
        // Instantiate in-memory store for KMS private keys.
        const privateKeyStore = new store_managed_key_js_1.PrivateKeyStoreMemory();
        // Instantiate local KMS using in-memory key stores.
        const kms = new kms_local_js_1.LocalKms({ kmsName: 'memory', keyStore, privateKeyStore });
        return { memory: kms };
    }
}
exports.KeyManager = KeyManager;
//# sourceMappingURL=key-manager.js.map