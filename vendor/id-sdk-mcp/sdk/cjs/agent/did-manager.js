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
exports.DidManager = exports.DidMessage = void 0;
const index_js_1 = require("../crypto/index.js");
const index_js_2 = require("../dids/index.js");
const store_managed_did_js_1 = require("./store-managed-did.js");
var DidMessage;
(function (DidMessage) {
    DidMessage["Create"] = "Create";
    DidMessage["Resolve"] = "Resolve";
})(DidMessage || (exports.DidMessage = DidMessage = {}));
class DidManager {
    constructor(options) {
        this._didMethods = new Map();
        const { agent, didMethods, store } = options;
        this._agent = agent;
        this._store = store !== null && store !== void 0 ? store : new store_managed_did_js_1.DidStoreMemory();
        if (!didMethods) {
            throw new TypeError(`DidManager: Required parameter missing: 'didMethods'`);
        }
        for (const didMethod of didMethods) {
            this._didMethods.set(didMethod.methodName, didMethod);
        }
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
            throw new Error('DidManager: Unable to determine agent execution context.');
        }
        return this._agent;
    }
    set agent(agent) {
        this._agent = agent;
    }
    async create(options) {
        let { alias, keySet, kms, metadata, method, context } = options, methodOptions = __rest(options, ["alias", "keySet", "kms", "metadata", "method", "context"]);
        // Get the DID method implementation.
        const didMethod = this.getMethod(method);
        // If keySet not given, generate a DID method specific key set.
        if ((keySet === null || keySet === void 0 ? void 0 : keySet.verificationMethodKeys) === undefined) {
            keySet = await didMethod.generateKeySet();
        }
        /** Import key set to KeyManager, or if already in KeyManager, retrieve the
         * public key. */
        keySet = await this.importOrGetKeySet({ keySet, kms });
        // Create a DID.
        const did = await didMethod.create(Object.assign(Object.assign({}, methodOptions), { keySet }));
        // Set the KeyManager alias for each key to the DID Document primary ID.
        await this.updateKeySet({
            canonicalId: did.canonicalId,
            didDocument: did.document,
            keySet
        });
        // Merged given metadata and format as a ManagedDid.
        const mergedMetadata = Object.assign(Object.assign({}, metadata), did.metadata);
        const managedDid = Object.assign(Object.assign({ alias, method }, did), { metadata: mergedMetadata });
        /** If context is undefined, then the DID will be stored under the
         * tenant of the created DID. Otherwise, the DID record will
         * be stored under the tenant of the specified context. */
        context !== null && context !== void 0 ? context : (context = managedDid.did);
        // Store the ManagedDid in the store.
        await this._store.importDid({ did: managedDid, agent: this.agent, context });
        return managedDid;
    }
    async getDefaultSigningKey(options) {
        const { did } = options;
        // Resolve the DID to a DID Document.
        const { didDocument } = await this.agent.didResolver.resolve(did);
        // Get the DID method implementation.
        const parsedDid = index_js_2.utils.parseDid({ didUrl: did });
        if (!(didDocument && parsedDid)) {
            throw new Error(`DidManager: Unable to resolve: ${did}`);
        }
        const didMethod = this.getMethod(parsedDid.method);
        // Retrieve the DID method specific default signing key.
        const verificationMethodId = await didMethod.getDefaultSigningKey({ didDocument });
        return verificationMethodId;
    }
    async get(options) {
        let did;
        const { context, didRef } = options;
        // Try to get DID by ID.
        did = await this._store.getDid({ did: didRef, agent: this.agent, context });
        if (did)
            return did;
        // Try to find DID by alias.
        did = await this._store.findDid({ alias: didRef, agent: this.agent, context });
        if (did)
            return did;
        return undefined;
    }
    async import(options) {
        let { alias, context, did, kms } = options;
        if (did.keySet === undefined) {
            throw new Error(`Portable DID is missing required property: 'keySet'`);
        }
        // Verify the DID method is supported.
        const parsedDid = index_js_2.utils.parseDid({ didUrl: did.did });
        if (!parsedDid) {
            throw new Error(`DidManager: Unable to resolve: ${did}`);
        }
        const { method } = parsedDid;
        this.getMethod(method);
        /** Import key set to KeyManager, or if already in KeyManager, retrieve the
         * public key. */
        const keySet = await this.importOrGetKeySet({ keySet: did.keySet, kms });
        // Set the KeyManager alias for each key to the DID Document primary ID.
        await this.updateKeySet({
            canonicalId: did.canonicalId,
            didDocument: did.document,
            keySet
        });
        // Format the PortableDid and given input as a ManagedDid.
        const managedDid = Object.assign(Object.assign({ alias, method }, did), { keySet });
        /** If context is undefined, then the DID will be stored under the
         * tenant of the imported DID. Otherwise, the DID record will
         * be stored under the tenant of the specified context. */
        context !== null && context !== void 0 ? context : (context = managedDid.did);
        // Store the ManagedDid in the store.
        await this._store.importDid({ did: managedDid, agent: this.agent, context });
        return managedDid;
    }
    /**
     * Retrieves a `DidMethodApi` instance associated with a specific method
     * name. This method uses the method name to access the `didMethods` map
     * and returns the corresponding `DidMethodApi` instance. If a method
     * name is provided that does not exist within the `didMethods` map, it
     * will throw an error.
     *
     * @param methodName - A string representing the name of the method for
     * which the corresponding `DidMethodApi` instance is to be retrieved.
     *
     * @returns The `DidMethodApi` instance that corresponds to the provided
     * method name. If no `DidMethodApi` instance corresponds to the provided
     * method name, an error is thrown.
     *
     * @throws Will throw an error if the provided method name does not
     * correspond to any `DidMethodApi` instance within the `didMethods` map.
     */
    getMethod(methodName) {
        const didMethod = this._didMethods.get(methodName);
        if (didMethod === undefined) {
            throw new Error(`The DID method '${methodName}' is not supported`);
        }
        return didMethod;
    }
    async importOrGetKeySet(options) {
        const { kms } = options;
        // Get the agent instance.
        const agent = this.agent;
        // Make a deep copy of the key set to prevent side effects.
        const keySet = structuredClone(options.keySet);
        for (let key of keySet.verificationMethodKeys) {
            /**
             * The key has no `keyManagerId` value, indicating it is not present in
             * the KeyManager store. Import each key into KeyManager.
             */
            if (key.keyManagerId === undefined) {
                if ('publicKeyJwk' in key && 'privateKeyJwk' in key
                    && key.publicKeyJwk && key.privateKeyJwk) {
                    // Import key pair to KeyManager.
                    const publicKey = await index_js_1.Jose.jwkToCryptoKey({ key: key.publicKeyJwk });
                    const privateKey = await index_js_1.Jose.jwkToCryptoKey({ key: key.privateKeyJwk });
                    const importedKeyPair = await agent.keyManager.importKey({
                        privateKey: Object.assign(Object.assign({ kms: kms }, privateKey), { material: privateKey.material }),
                        publicKey: Object.assign(Object.assign({ kms: kms }, publicKey), { material: publicKey.material })
                    });
                    // Store the UUID assigned by KeyManager.
                    key.keyManagerId = importedKeyPair.privateKey.id;
                    // Delete the private key.
                    delete key.privateKeyJwk;
                }
                else if ('publicKeyJwk' in key && key.publicKeyJwk) {
                    // Import only public key.
                    const publicKey = await index_js_1.Jose.jwkToCryptoKey({ key: key.publicKeyJwk });
                    const importedPublicKey = await agent.keyManager.importKey(Object.assign(Object.assign({ kms: kms }, publicKey), { material: publicKey.material }));
                    // Store the UUID assigned by KeyManager.
                    key.keyManagerId = importedPublicKey.id;
                }
                else {
                    throw new Error(`Required parameter(s) missing: 'publicKeyJwk', and optionally, 'privateKeyJwk`);
                }
                /**
                 * The key does have a `keyManagerId` value so retrieve the public key
                 * from the KeyManager store.
                 */
            }
            else {
                const keyOrKeyPair = await agent.keyManager.getKey({ keyRef: key.keyManagerId });
                if (!keyOrKeyPair)
                    throw new Error(`Key with ID '${key.keyManagerId} not found.`);
                const publicKey = 'publicKey' in keyOrKeyPair ? keyOrKeyPair.publicKey : keyOrKeyPair;
                // Convert public key from CryptoKey to JWK format.
                key.publicKeyJwk = await index_js_1.Jose.cryptoKeyToJwk({ key: publicKey });
            }
        }
        return keySet;
    }
    async processRequest(request) {
        const { messageOptions, messageType, store: _ } = request;
        switch (messageType) {
            case DidMessage.Create: {
                const result = await this.create(messageOptions);
                return { result };
                break;
            }
            default: {
                throw new Error(`DidManager: Unsupported request type: ${messageType}`);
            }
        }
    }
    /**
     * Set the KeyManager alias for each key to the DID primary ID.
     *
     * If defined, use the `canonicalId` as the primary ID for the
     * DID subject. Otherwise, use the `id` property from the topmost
     * map of the DID document.
     *
     * @see {@link https://www.w3.org/TR/did-core/#did-subject | DID Subject}
     * @see {@link https://www.w3.org/TR/did-core/#dfn-canonicalid | DID Document Metadata}
     */
    async updateKeySet(options) {
        const { canonicalId, didDocument, keySet, } = options;
        // Get the agent instance.
        const agent = this.agent;
        // DID primary ID is the canonicalId, if present, or the DID document `id`.
        const didPrimaryId = canonicalId !== null && canonicalId !== void 0 ? canonicalId : didDocument.id;
        for (let keyPair of keySet.verificationMethodKeys) {
            /** Compute the multibase ID for the JWK in case the DID method uses
                 * publicKeyMultibase format. */
            const publicKeyMultibase = await index_js_1.Jose.jwkToMultibaseId({ key: keyPair.publicKeyJwk });
            // Find the verification method ID of the key in the DID document.
            const methodId = index_js_2.utils.getVerificationMethodIds({
                didDocument,
                publicKeyJwk: keyPair.publicKeyJwk,
                publicKeyMultibase
            });
            if (!(methodId && methodId.includes('#'))) {
                throw new Error('DidManager: Unable to update key set due to malformed verification method ID');
            }
            /** Construct the key alias given the DID's primary ID and the key's
             * verification method ID. */
            const [, fragment] = methodId.split('#');
            const keyAlias = `${didPrimaryId}#${fragment}`;
            // Set the KeyManager alias to the method ID.
            await agent.keyManager.updateKey({ keyRef: keyPair.keyManagerId, alias: keyAlias });
        }
    }
}
exports.DidManager = DidManager;
//# sourceMappingURL=did-manager.js.map