"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.LocalKms = exports.defaultAlgorithms = void 0;
const cryptoUtils = __importStar(require("../crypto/utils.js"));
const index_js_1 = require("../crypto/index.js");
const utils_js_1 = require("./utils.js");
const store_managed_key_js_1 = require("./store-managed-key.js");
// Map key operations to algorithm specs to implementations.
exports.defaultAlgorithms = {
    'AES-CTR': index_js_1.AesCtrAlgorithm,
    ECDH: index_js_1.EcdhAlgorithm,
    ECDSA: index_js_1.EcdsaAlgorithm,
    EdDSA: index_js_1.EdDsaAlgorithm,
};
class LocalKms {
    constructor(options) {
        this._supportedAlgorithms = new Map();
        const { agent, kmsName, keyStore, privateKeyStore } = options;
        this._agent = agent;
        this._name = kmsName;
        this._keyStore = keyStore !== null && keyStore !== void 0 ? keyStore : new store_managed_key_js_1.KeyStoreMemory();
        this._privateKeyStore = privateKeyStore !== null && privateKeyStore !== void 0 ? privateKeyStore : new store_managed_key_js_1.PrivateKeyStoreMemory();
        // Merge the default and custom algorithms and register with the KMS.
        const cryptoAlgorithms = Object.assign(Object.assign({}, exports.defaultAlgorithms), options.cryptoAlgorithms);
        this.registerSupportedAlgorithms(cryptoAlgorithms);
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
    }
    async decrypt(options) {
        const { algorithm, data, keyRef } = options;
        // Retrieve the ManagedKey from the KMS key metadata store.
        const key = await this.getKey({ keyRef });
        if ((0, utils_js_1.isManagedKey)(key)) {
            const privateManagedKey = await this._privateKeyStore.getKey({
                id: key.id,
                agent: this.agent
            });
            if (privateManagedKey !== undefined) {
                // Construct a CryptoKey object from the key metadata and private key material.
                const privateCryptoKey = this.toCryptoKey(Object.assign(Object.assign({}, key), { material: privateManagedKey.material }));
                // Decrypt the data.
                const cryptoAlgorithm = this.getAlgorithm(algorithm);
                const plaintext = cryptoAlgorithm.decrypt({ algorithm, key: privateCryptoKey, data });
                return plaintext;
            }
        }
        throw new Error(`Operation failed: 'decrypt'. Key not found: ${keyRef}`);
    }
    async deriveBits(options) {
        let { algorithm, baseKeyRef, length } = options;
        // Retrieve the ManagedKeyPair from the KMS key metadata store.
        const ownKeyPair = await this.getKey({ keyRef: baseKeyRef });
        if ((0, utils_js_1.isManagedKeyPair)(ownKeyPair)) {
            const privateManagedKey = await this._privateKeyStore.getKey({
                id: ownKeyPair.privateKey.id,
                agent: this.agent
            });
            if (privateManagedKey !== undefined) {
                // Construct a CryptoKey object from the key metadata and private key material.
                const privateCryptoKey = this.toCryptoKey(Object.assign(Object.assign({}, ownKeyPair.privateKey), { material: privateManagedKey.material }));
                // Derive the shared secret.
                const cryptoAlgorithm = this.getAlgorithm(algorithm);
                const sharedSecret = cryptoAlgorithm.deriveBits({ algorithm, baseKey: privateCryptoKey, length: length !== null && length !== void 0 ? length : null });
                return sharedSecret;
            }
        }
        throw new Error(`Operation failed: 'deriveBits'. Key not found: ${baseKeyRef}`);
    }
    async encrypt(options) {
        const { algorithm, data, keyRef } = options;
        // Retrieve the ManagedKey from the KMS key metadata store.
        const key = await this.getKey({ keyRef });
        if ((0, utils_js_1.isManagedKey)(key)) {
            const privateManagedKey = await this._privateKeyStore.getKey({
                id: key.id,
                agent: this.agent
            });
            if (privateManagedKey !== undefined) {
                // Construct a CryptoKey object from the key metadata and private key material.
                const privateCryptoKey = this.toCryptoKey(Object.assign(Object.assign({}, key), { material: privateManagedKey.material }));
                // Encrypt the data.
                const cryptoAlgorithm = this.getAlgorithm(algorithm);
                const ciphertext = cryptoAlgorithm.encrypt({ algorithm, key: privateCryptoKey, data });
                return ciphertext;
            }
        }
        throw new Error(`Operation failed: 'encrypt'. Key not found: ${keyRef}`);
    }
    async generateKey(options) {
        let { algorithm, alias, extractable, keyUsages, metadata } = options;
        // Get crypto algorithm implementation.
        const cryptoAlgorithm = this.getAlgorithm(algorithm);
        // Generate the key.
        extractable !== null && extractable !== void 0 ? extractable : (extractable = true); // Default to extractable if not specified.
        const cryptoKey = await cryptoAlgorithm.generateKey({ algorithm, extractable, keyUsages });
        // Create a ManagedKey or ManagedKeyPair using the generated key and store the private key material.
        let managedKeyOrKeyPair;
        if (cryptoUtils.isCryptoKeyPair(cryptoKey)) {
            const privateKeyType = cryptoKey.privateKey.type;
            const id = await this._privateKeyStore.importKey({
                key: { material: cryptoKey.privateKey.material, type: privateKeyType },
                agent: this.agent
            });
            const managedKeyPair = {
                privateKey: this.toManagedKey(Object.assign(Object.assign({}, cryptoKey.privateKey), { id, alias, metadata })),
                publicKey: this.toManagedKey(Object.assign(Object.assign({}, cryptoKey.publicKey), { material: cryptoKey.publicKey.material, id, alias, metadata }))
            };
            managedKeyOrKeyPair = managedKeyPair;
        }
        else {
            const keyType = cryptoKey.type;
            const id = await this._privateKeyStore.importKey({
                key: { material: cryptoKey.material, type: keyType },
                agent: this.agent
            });
            managedKeyOrKeyPair = this.toManagedKey(Object.assign(Object.assign({}, cryptoKey), { id, alias, metadata }));
        }
        // Store the ManagedKey or ManagedKeyPair in the KMS key store.
        await this._keyStore.importKey({ key: managedKeyOrKeyPair, agent: this.agent });
        return managedKeyOrKeyPair;
    }
    async getKey(options) {
        const keyOrKeyPair = this._keyStore.getKey({ id: options.keyRef, agent: this.agent });
        return keyOrKeyPair;
    }
    async importKey(options) {
        if ('privateKey' in options) {
            // Asymmetric key pair import.
            const { privateKey, publicKey } = options;
            if (privateKey.type === 'public' && publicKey.type === 'private')
                throw new Error(`Import failed due to private and public key mismatch`);
            if (!(privateKey.type === 'private' && publicKey.type === 'public'))
                throw new TypeError(`Out of range: '${privateKey.type}, ${publicKey.type}'. Must be 'private, public'`);
            const id = await this._privateKeyStore.importKey({
                key: { material: privateKey.material, type: privateKey.type },
                agent: this.agent
            });
            const managedKeyPair = {
                privateKey: this.toManagedKey(Object.assign(Object.assign({}, privateKey), { id, material: undefined })),
                publicKey: this.toManagedKey(Object.assign(Object.assign({}, publicKey), { material: publicKey.material, id }))
            };
            await this._keyStore.importKey({ key: managedKeyPair, agent: this.agent });
            return managedKeyPair;
        }
        const keyType = options.type;
        switch (keyType) {
            case 'private': {
                // Asymmetric private key import.
                const material = options.material;
                const id = await this._privateKeyStore.importKey({
                    key: { material, type: keyType },
                    agent: this.agent
                });
                const privateManagedKey = this.toManagedKey(Object.assign(Object.assign({}, options), { material: undefined, id }));
                await this._keyStore.importKey({ key: privateManagedKey, agent: this.agent });
                return privateManagedKey;
            }
            case 'public': {
                // Asymmetric public key import.
                const material = options.material;
                const publicManagedKey = this.toManagedKey(Object.assign(Object.assign({}, options), { material, id: '' }));
                publicManagedKey.id = await this._keyStore.importKey({ key: publicManagedKey, agent: this.agent });
                return publicManagedKey;
            }
            case 'secret': {
                // Symmetric secret key import.
                const material = options.material;
                const id = await this._privateKeyStore.importKey({
                    key: { material, type: keyType },
                    agent: this.agent
                });
                const secretManagedKey = this.toManagedKey(Object.assign(Object.assign({}, options), { material: undefined, id }));
                await this._keyStore.importKey({ key: secretManagedKey, agent: this.agent });
                return secretManagedKey;
            }
            default:
                throw new TypeError(`Out of range: '${keyType}'. Must be one of 'private, public, secret'`);
        }
    }
    async sign(options) {
        const { algorithm, data, keyRef } = options;
        // Retrieve the ManagedKeyPair from the KMS key metadata store.
        const keyPair = await this.getKey({ keyRef });
        if ((0, utils_js_1.isManagedKeyPair)(keyPair)) {
            const privateManagedKey = await this._privateKeyStore.getKey({
                id: keyPair.privateKey.id,
                agent: this.agent
            });
            if (privateManagedKey !== undefined) {
                // Construct a CryptoKey object from the key metadata and private key material.
                const privateCryptoKey = this.toCryptoKey(Object.assign(Object.assign({}, keyPair.privateKey), { material: privateManagedKey.material }));
                // Sign the data.
                const cryptoAlgorithm = this.getAlgorithm(algorithm);
                const signature = cryptoAlgorithm.sign({ algorithm, key: privateCryptoKey, data });
                return signature;
            }
        }
        throw new Error(`Operation failed: 'sign'. Key not found: ${keyRef}`);
    }
    async updateKey(options) {
        const { keyRef, alias, metadata } = options;
        const keyOrKeyPair = await this.getKey({ keyRef });
        if (!keyOrKeyPair) {
            throw new Error(`Key not found: '${keyRef}'`);
        }
        const keyId = ((0, utils_js_1.isManagedKeyPair)(keyOrKeyPair))
            ? keyOrKeyPair.publicKey.id
            : keyOrKeyPair.id;
        // Update the KMS key metadata store.
        return this._keyStore.updateKey({ id: keyId, alias, metadata, agent: this.agent });
    }
    async verify(options) {
        const { algorithm, data, keyRef, signature } = options;
        // Retrieve the ManagedKeyPair from the KMS key metadata store.
        const keyPair = await this.getKey({ keyRef });
        if ((0, utils_js_1.isManagedKeyPair)(keyPair)) {
            if (keyPair.publicKey.material === undefined) {
                throw new Error(`Required property missing: 'material'`);
            }
            // Construct a CryptoKey object from the key metadata and private key material.
            const publicCryptoKey = this.toCryptoKey(Object.assign(Object.assign({}, keyPair.publicKey), { material: keyPair.publicKey.material }));
            // Verify the signature and data.
            const cryptoAlgorithm = this.getAlgorithm(algorithm);
            const isValid = cryptoAlgorithm.verify({ algorithm, key: publicCryptoKey, signature, data });
            return isValid;
        }
        throw new Error(`Operation failed: 'verify'. Key not found: ${keyRef}`);
    }
    getAlgorithm(algorithmIdentifier) {
        cryptoUtils.checkRequiredProperty({ property: 'name', inObject: algorithmIdentifier });
        const algorithm = this._supportedAlgorithms.get(algorithmIdentifier.name.toUpperCase());
        if (algorithm === undefined) {
            throw new Error(`The algorithm '${algorithmIdentifier.name}' is not supported`);
        }
        return algorithm.create();
    }
    registerSupportedAlgorithms(cryptoAlgorithms) {
        for (const [name, implementation] of Object.entries(cryptoAlgorithms)) {
            // Add the algorithm name and its implementation to the supported algorithms map,
            // upper-cased to allow for case-insensitive.
            this._supportedAlgorithms.set(name.toUpperCase(), implementation);
        }
    }
    toCryptoKey(managedKey) {
        const cryptoKey = {
            algorithm: managedKey.algorithm,
            extractable: managedKey.extractable,
            material: managedKey.material,
            type: managedKey.type,
            usages: managedKey.usages
        };
        return cryptoKey;
    }
    toManagedKey(options) {
        const managedKey = {
            id: options.id,
            algorithm: options.algorithm,
            alias: options.alias,
            extractable: options.extractable,
            kms: this._name,
            material: (options.type === 'public') ? options.material : undefined,
            metadata: options.metadata,
            state: 'Enabled',
            type: options.type,
            usages: options.usages
        };
        return managedKey;
    }
}
exports.LocalKms = LocalKms;
//# sourceMappingURL=kms-local.js.map