var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
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
import { LocalKms } from './kms-local.js';
import { isManagedKey, isManagedKeyPair } from './utils.js';
import { KeyStoreMemory, PrivateKeyStoreMemory } from './store-managed-key.js';
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
export class KeyManager {
    constructor(options) {
        let { agent, kms, store } = options !== null && options !== void 0 ? options : {};
        this._agent = agent;
        this._store = store !== null && store !== void 0 ? store : new KeyStoreMemory();
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
    decrypt(options) {
        return __awaiter(this, void 0, void 0, function* () {
            let { keyRef } = options, decryptOptions = __rest(options, ["keyRef"]);
            const key = yield this.getKey({ keyRef });
            if (!isManagedKey(key)) {
                throw new Error(`Key not found: '${keyRef}'`);
            }
            const kmsName = key.kms;
            const kms = this.getKms(kmsName);
            const keyId = key.id;
            const plaintext = yield kms.decrypt(Object.assign({ keyRef: keyId }, decryptOptions));
            return plaintext;
        });
    }
    deriveBits(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const { baseKeyRef } = options, deriveBitsOptions = __rest(options, ["baseKeyRef"]);
            const ownKeyPair = yield this.getKey({ keyRef: baseKeyRef });
            if (!isManagedKeyPair(ownKeyPair)) {
                throw new Error(`Key not found: '${baseKeyRef}'`);
            }
            const kmsName = ownKeyPair.privateKey.kms;
            const kms = this.getKms(kmsName);
            const ownKeyId = ownKeyPair.privateKey.id;
            const sharedSecret = kms.deriveBits(Object.assign({ baseKeyRef: ownKeyId }, deriveBitsOptions));
            return sharedSecret;
        });
    }
    encrypt(options) {
        return __awaiter(this, void 0, void 0, function* () {
            let { keyRef } = options, encryptOptions = __rest(options, ["keyRef"]);
            const key = yield this.getKey({ keyRef });
            if (!isManagedKey(key)) {
                throw new Error(`Key not found: '${keyRef}'`);
            }
            const kmsName = key.kms;
            const kms = this.getKms(kmsName);
            const keyId = key.id;
            const ciphertext = yield kms.encrypt(Object.assign({ keyRef: keyId }, encryptOptions));
            return ciphertext;
        });
    }
    generateKey(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const { kms: kmsName } = options, generateKeyOptions = __rest(options, ["kms"]);
            const kms = this.getKms(kmsName);
            const keyOrKeyPair = yield kms.generateKey(generateKeyOptions);
            // Store the ManagedKey or ManagedKeyPair in KeyManager's key store.
            yield this._store.importKey({ key: keyOrKeyPair, agent: this.agent });
            return keyOrKeyPair;
        });
    }
    getKey({ keyRef }) {
        var _a, _b;
        return __awaiter(this, void 0, void 0, function* () {
            let keyOrKeyPair;
            // First, check to see if the requested key is the default signing key.
            const defaultSigningKeyId = (_a = this._defaultSigningKey) === null || _a === void 0 ? void 0 : _a.publicKey.id;
            const defaultSigningKeyAlias = (_b = this._defaultSigningKey) === null || _b === void 0 ? void 0 : _b.publicKey.alias;
            if (keyRef === defaultSigningKeyId || keyRef === defaultSigningKeyAlias) {
                return this._defaultSigningKey;
            }
            // Try to get key by ID.
            keyOrKeyPair = yield this._store.getKey({ id: keyRef, agent: this.agent });
            if (keyOrKeyPair)
                return keyOrKeyPair;
            // Try to find key by alias.
            keyOrKeyPair = yield this._store.findKey({ alias: keyRef, agent: this.agent });
            if (keyOrKeyPair)
                return keyOrKeyPair;
            return undefined;
        });
    }
    importKey(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const kmsName = ('privateKey' in options) ? options.privateKey.kms : options.kms;
            const kms = this.getKms(kmsName);
            // Store the ManagedKey or ManagedKeyPair in the given KMS.
            const importedKeyOrKeyPair = yield kms.importKey(options);
            // Store the ManagedKey or ManagedKeyPair in KeyManager's key store.
            yield this._store.importKey({ key: importedKeyOrKeyPair, agent: this.agent });
            return importedKeyOrKeyPair;
        });
    }
    listKms() {
        return Array.from(this._kms.keys());
    }
    setDefaultSigningKey({ key }) {
        return __awaiter(this, void 0, void 0, function* () {
            const kmsName = key.privateKey.kms;
            const kms = this.getKms(kmsName);
            // Store the default signing key pair in an in-memory KMS.
            const importedDefaultSigningKey = yield kms.importKey(key);
            // Set the in-memory key to be KeyManager's default signing key.
            this._defaultSigningKey = importedDefaultSigningKey;
        });
    }
    sign(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const { keyRef } = options, signOptions = __rest(options, ["keyRef"]);
            const keyPair = yield this.getKey({ keyRef });
            if (!isManagedKeyPair(keyPair)) {
                throw new Error(`Key not found: '${keyRef}'`);
            }
            const kmsName = keyPair.privateKey.kms;
            const kms = this.getKms(kmsName);
            const keyId = keyPair.privateKey.id;
            const signature = yield kms.sign(Object.assign({ keyRef: keyId }, signOptions));
            return signature;
        });
    }
    updateKey(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const { keyRef, alias, metadata } = options;
            const keyOrKeyPair = yield this.getKey({ keyRef });
            if (!keyOrKeyPair) {
                throw new Error(`Key not found: '${keyRef}'`);
            }
            const { id: keyId, kms: kmsName } = (isManagedKeyPair(keyOrKeyPair))
                ? Object.assign({}, keyOrKeyPair.publicKey) : Object.assign({}, keyOrKeyPair);
            // Update the ManagedKey or ManagedKeyPair in the given KMS.
            const kms = this.getKms(kmsName);
            const kmsUpdated = yield kms.updateKey(options);
            if (!kmsUpdated)
                return false;
            // Since the KMS was successfully updated, update the KeyManager store.
            return yield this._store.updateKey({ id: keyId, alias, metadata, agent: this.agent });
        });
    }
    verify(options) {
        return __awaiter(this, void 0, void 0, function* () {
            let { keyRef } = options, verifyOptions = __rest(options, ["keyRef"]);
            const keyPair = yield this.getKey({ keyRef });
            if (!isManagedKeyPair(keyPair)) {
                throw new Error(`Key not found: '${keyRef}'`);
            }
            const kmsName = keyPair.publicKey.kms;
            const kms = this.getKms(kmsName);
            const keyId = keyPair.publicKey.id;
            const isValid = yield kms.verify(Object.assign({ keyRef: keyId }, verifyOptions));
            return isValid;
        });
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
        const keyStore = new KeyStoreMemory();
        // Instantiate in-memory store for KMS private keys.
        const privateKeyStore = new PrivateKeyStoreMemory();
        // Instantiate local KMS using in-memory key stores.
        const kms = new LocalKms({ kmsName: 'memory', keyStore, privateKeyStore });
        return { memory: kms };
    }
}
//# sourceMappingURL=key-manager.js.map