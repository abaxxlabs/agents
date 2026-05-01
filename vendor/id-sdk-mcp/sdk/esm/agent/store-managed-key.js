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
import * as cryptoUtils from '../crypto/utils.js';
import { Convert, removeEmptyObjects, removeUndefinedProperties } from '../common/index.js';
import { isManagedKeyPair } from './utils.js';
/**
 * An implementation of `ManagedKeyStore` that stores key metadata and
 * public key material in a DWN.
 *
 * An instance of this class can be used by `KeyManager` or
 * an implementation of `KeyManagementSystem`.
 */
export class KeyStoreDwn {
    constructor(options) {
        this._keyRecordProperties = {
            dataFormat: 'application/json',
            schema: 'https://abaxx.tech/schemas/dwn/managed-key'
        };
        const { schema } = options !== null && options !== void 0 ? options : {};
        if (schema) {
            this._keyRecordProperties.schema = schema;
        }
    }
    deleteKey(options) {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
            const { agent, context, id } = options;
            // Determine which DID to use to author DWN messages.
            const authorDid = yield this.getAuthor({ agent, context });
            // Query the DWN for all stored key objects.
            const { reply: queryReply } = yield this.getKeyRecords(agent, context);
            // Loop through all of the entries and try to find a match.
            let matchingRecordId;
            for (const record of (_a = queryReply.entries) !== null && _a !== void 0 ? _a : []) {
                // @ts-ignore
                if (record.encodedData) {
                    // @ts-ignore
                    const storedKey = this.decodeKey(record.encodedData);
                    const storedKeyId = isManagedKeyPair(storedKey) ? storedKey.publicKey.id : storedKey.id;
                    if (storedKey && storedKeyId === id) {
                        matchingRecordId = record.recordId;
                        break;
                    }
                }
            }
            // Return undefined if the specified key was not found in the store.
            if (!matchingRecordId)
                return false;
            // If a record for the specified key was found, attempt to delete it.
            const { reply: { status } } = yield agent.dwnManager.processRequest({
                author: authorDid,
                target: authorDid,
                messageType: 'RecordsDelete',
                messageOptions: {
                    recordId: matchingRecordId
                }
            });
            // If the key was successfully deleted, return true;
            if (status.code === 202)
                return true;
            // If the key could not be deleted, return false;
            return false;
        });
    }
    findKey(options) {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
            const { agent, alias, context, id } = options;
            // Query the DWN for all stored managed key objects.
            const { reply: queryReply } = yield this.getKeyRecords(agent, context);
            // Loop through all of the entries and return a match, if found.
            for (const record of (_a = queryReply.entries) !== null && _a !== void 0 ? _a : []) {
                // @ts-ignore
                if (record.encodedData) {
                    // @ts-ignore
                    const storedKey = this.decodeKey(record.encodedData);
                    if (isManagedKeyPair(storedKey)) {
                        if (storedKey.publicKey.id === id)
                            return storedKey;
                        if (storedKey.publicKey.alias === alias)
                            return storedKey;
                    }
                    else {
                        if (storedKey.id === id)
                            return storedKey;
                        if (storedKey.alias === alias)
                            return storedKey;
                    }
                }
            }
            // Return undefined if no matches were found.
            return undefined;
        });
    }
    getKey(options) {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
            const { agent, context, id } = options;
            // Query the DWN for all stored managed key objects.
            const { reply: queryReply } = yield this.getKeyRecords(agent, context);
            // Loop through all of the entries and return a match, if found.
            for (const record of (_a = queryReply.entries) !== null && _a !== void 0 ? _a : []) {
                // @ts-ignore
                if (record.encodedData) {
                    // @ts-ignore
                    const storedKey = this.decodeKey(record.encodedData);
                    const storedKeyId = isManagedKeyPair(storedKey) ? storedKey.publicKey.id : storedKey.id;
                    if (storedKeyId === id)
                        return storedKey;
                }
            }
            // Return undefined if no matches were found.
            return undefined;
        });
    }
    importKey(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const { agent, context, key } = options;
            let keyId;
            if (isManagedKeyPair(key)) {
                keyId = key.publicKey.id;
            }
            else {
                // If an ID wasn't specified, generate one.
                if (!key.id) {
                    key.id = cryptoUtils.randomUuid();
                }
                keyId = key.id;
            }
            // Determine which DID to use to author DWN messages.
            const authorDid = yield this.getAuthor({ agent, context });
            // Check if the key being imported is already present in the store.
            const duplicateFound = yield this.getKey({ agent, context, id: keyId });
            if (duplicateFound) {
                throw new Error(`KeyStoreDwn: Key with ID already exists: '${keyId}'`);
            }
            // Encode the managed key or key pair as bytes.
            const encodedKey = this.encodeKey(key);
            const { reply: { status } } = yield agent.dwnManager.processRequest({
                author: authorDid,
                target: authorDid,
                messageType: 'RecordsWrite',
                messageOptions: Object.assign({}, this._keyRecordProperties),
                // @ts-ignore
                dataStream: new Blob([encodedKey])
            });
            // If the write fails, throw an error.
            if (status.code !== 202) {
                throw new Error('DidStoreDwn: Failed to write imported DID to store.');
            }
            return keyId;
        });
    }
    listKeys(options) {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
            const { agent, context } = options;
            // Query the DWN for all stored managed key objects.
            const { reply: queryReply } = yield this.getKeyRecords(agent, context);
            // Loop through all of the entries and accumulate the key objects.
            let storedKeys = [];
            for (const record of (_a = queryReply.entries) !== null && _a !== void 0 ? _a : []) {
                // @ts-ignore
                if (record.encodedData) {
                    // @ts-ignore
                    const storedKey = this.decodeKey(record.encodedData);
                    storedKeys.push(storedKey);
                }
            }
            return storedKeys;
        });
    }
    updateKey(options) {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
            const { agent, context, id } = options;
            const propertyUpdates = { alias: options.alias, metadata: options.metadata };
            // Determine which DID to use to author DWN messages.
            const authorDid = yield this.getAuthor({ agent, context });
            // Query the DWN for all stored managed key objects.
            const { reply: queryReply } = yield this.getKeyRecords(agent, context);
            // Confirm the key being updated is already present in the store.
            let keyToUpdate;
            let recordToUpdate;
            for (const entry of (_a = queryReply.entries) !== null && _a !== void 0 ? _a : []) {
                // @ts-ignore
                const { encodedData } = entry, record = __rest(entry, ["encodedData"]);
                if (encodedData) {
                    const storedKey = this.decodeKey(encodedData);
                    const storedKeyId = isManagedKeyPair(storedKey) ? storedKey.publicKey.id : storedKey.id;
                    if (storedKey && storedKeyId === id) {
                        keyToUpdate = storedKey;
                        recordToUpdate = record;
                        break;
                    }
                }
            }
            // Key with given ID not present so update operation cannot proceed.
            if (!recordToUpdate || !keyToUpdate)
                return false;
            // Make a deep copy of the update properties to ensure all nested objects do not share references.
            removeUndefinedProperties(propertyUpdates);
            removeEmptyObjects(propertyUpdates);
            const clonedUpdates = structuredClone(propertyUpdates);
            // Update the given properties of the key.
            if (isManagedKeyPair(keyToUpdate)) {
                keyToUpdate.privateKey = Object.assign(Object.assign({}, keyToUpdate.privateKey), clonedUpdates);
                keyToUpdate.publicKey = Object.assign(Object.assign({}, keyToUpdate.publicKey), clonedUpdates);
            }
            else {
                keyToUpdate = Object.assign(Object.assign({}, keyToUpdate), clonedUpdates);
            }
            // Encode the updated key or key pair as bytes.
            const updatedKeyBytes = this.encodeKey(keyToUpdate);
            // Assemble the update messsage, including record ID and context ID, if any.
            let messageOptions = Object.assign({}, recordToUpdate.descriptor);
            messageOptions.contextId = recordToUpdate.contextId;
            messageOptions.recordId = recordToUpdate.recordId;
            /** Remove properties from the update messageOptions to let the DWN SDK
             * auto-fill.  Otherwisse, you will get 409 Conflict errors. */
            delete messageOptions.dataCid;
            delete messageOptions.dataSize;
            delete messageOptions.data;
            delete messageOptions.messageTimestamp;
            // Overwrite the entry in the store with the updated object.
            const { reply: { status } } = yield agent.dwnManager.processRequest({
                author: authorDid,
                target: authorDid,
                messageType: 'RecordsWrite',
                messageOptions,
                dataStream: new Blob([updatedKeyBytes])
            });
            // If the write fails, throw an error.
            if (status.code !== 202) {
                throw new Error('DidStoreDwn: Failed to write updated key to store.');
            }
            return true;
        });
    }
    decodeKey(keyEncodedData) {
        const encodedKey = Convert.base64Url(keyEncodedData).toObject();
        if ('publicKey' in encodedKey) {
            const privateKeyMaterial = encodedKey.privateKey.material
                ? Convert.base64Url(encodedKey.privateKey.material).toUint8Array()
                : undefined;
            const publicKeyMaterial = encodedKey.publicKey.material
                ? Convert.base64Url(encodedKey.publicKey.material).toUint8Array()
                : undefined;
            const managedKeyPair = {
                privateKey: Object.assign(Object.assign({}, encodedKey.privateKey), { material: privateKeyMaterial }),
                publicKey: Object.assign(Object.assign({}, encodedKey.publicKey), { material: publicKeyMaterial })
            };
            return managedKeyPair;
        }
        else {
            const material = encodedKey.material
                ? Convert.base64Url(encodedKey.material).toUint8Array()
                : undefined;
            const managedKey = Object.assign(Object.assign({}, encodedKey), { material });
            return managedKey;
        }
    }
    encodeKey(managedKey) {
        let encodedKey;
        if (isManagedKeyPair(managedKey)) {
            const privateKeyMaterial = managedKey.privateKey.material
                ? Convert.uint8Array(managedKey.privateKey.material).toBase64Url()
                : undefined;
            const publicKeyMaterial = managedKey.publicKey.material
                ? Convert.uint8Array(managedKey.publicKey.material).toBase64Url()
                : undefined;
            encodedKey = {
                privateKey: Object.assign(Object.assign({}, managedKey.privateKey), { material: privateKeyMaterial }),
                publicKey: Object.assign(Object.assign({}, managedKey.publicKey), { material: publicKeyMaterial })
            };
        }
        else {
            const material = managedKey.material
                ? Convert.uint8Array(managedKey.material).toBase64Url()
                : undefined;
            encodedKey = Object.assign(Object.assign({}, managedKey), { material });
        }
        const keyBytes = Convert.object(encodedKey).toUint8Array();
        return keyBytes;
    }
    getAuthor(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const { agent, context } = options;
            // If `context` is specified, DWN messages will be signed by this DID.
            if (context)
                return context;
            // If Agent has an agentDid, use it to sign DWN messages.
            if (agent.agentDid)
                return agent.agentDid;
            // If `context` and `agent.agentDid`are undefined, throw error.
            throw new Error(`KeyStoreDwn: Agent property 'agentDid' is undefined and no context was specified.`);
        });
    }
    getKeyRecords(agent, context) {
        return __awaiter(this, void 0, void 0, function* () {
            // Determine which DID to use to author DWN messages.
            const authorDid = yield this.getAuthor({ agent, context });
            const dwnResponse = yield agent.dwnManager.processRequest({
                author: authorDid,
                target: authorDid,
                messageType: 'RecordsQuery',
                messageOptions: {
                    filter: Object.assign({}, this._keyRecordProperties)
                }
            });
            return dwnResponse;
        });
    }
}
/**
 * An implementation of `ManagedKeyStore` that stores key metadata and
 * public key material in memory.
 *
 * An instance of this class can be used by `KeyManager` or
 * an implementation of `KeyManagementSystem`.
 */
export class KeyStoreMemory {
    constructor() {
        /**
         * A private field that contains the Map used as the in-memory key-value store.
         */
        this.store = new Map();
    }
    deleteKey({ id }) {
        return __awaiter(this, void 0, void 0, function* () {
            if (this.store.has(id)) {
                // Key with given ID exists so proceed with delete.
                this.store.delete(id);
                return true;
            }
            // Key with given ID not present so delete operation not possible.
            return false;
        });
    }
    findKey(options) {
        return __awaiter(this, void 0, void 0, function* () {
            let { alias, id } = options;
            // Get key by ID.
            if (id)
                return this.store.get(id);
            if (alias) {
                // Search through the store to find a matching entry.
                for (const key of yield this.listKeys()) {
                    if ('alias' in key && key.alias === alias)
                        return key;
                    if ('publicKey' in key && key.publicKey.alias === alias)
                        return key;
                }
            }
            return undefined;
        });
    }
    getKey({ id }) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.store.get(id);
        });
    }
    importKey({ key }) {
        return __awaiter(this, void 0, void 0, function* () {
            let id;
            if (isManagedKeyPair(key)) {
                id = key.publicKey.id;
            }
            else {
                // If an ID wasn't specified, generate one.
                if (!key.id) {
                    key.id = cryptoUtils.randomUuid();
                }
                id = key.id;
            }
            if (this.store.has(id)) {
                // Key with given ID already exists so import operation cannot proceed.
                throw new Error(`KeyStoreMemory: Key with ID already exists: '${id}'`);
            }
            // Make a deep copy of the key so that the object stored does not share the same references as the input key.
            const clonedKey = structuredClone(key);
            this.store.set(id, clonedKey);
            return id;
        });
    }
    listKeys() {
        return __awaiter(this, void 0, void 0, function* () {
            return Array.from(this.store.values());
        });
    }
    updateKey(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const id = options.id;
            const propertyUpdates = { alias: options.alias, metadata: options.metadata };
            const keyExists = this.store.has(id);
            if (!keyExists) {
                // Key with given ID not present so update operation cannot proceed.
                return false;
            }
            // Retrieve the current value of the key from the store.
            let key = yield this.getKey({ id });
            // Make a deep copy of the update properties to ensure all nested objects do not share references.
            removeUndefinedProperties(propertyUpdates);
            removeEmptyObjects(propertyUpdates);
            const clonedUpdates = structuredClone(propertyUpdates);
            // Update the given properties of the key.
            if (isManagedKeyPair(key)) {
                key.privateKey = Object.assign(Object.assign({}, key.privateKey), clonedUpdates);
                key.publicKey = Object.assign(Object.assign({}, key.publicKey), clonedUpdates);
            }
            else {
                key = Object.assign(Object.assign(Object.assign({}, key), clonedUpdates), { id: key.id });
            }
            // Overwrite the entry in the store with the updated object.
            this.store.set(id, key);
            return true;
        });
    }
}
/**
 * An implementation of `ManagedKeyStore` that stores private key
 * material in a DWN.
 *
 * An instance of this class can be used by an implementation of
 * `KeyManagementSystem`.
 */
export class PrivateKeyStoreDwn {
    constructor() {
        this._keyRecordProperties = {
            dataFormat: 'application/json',
            schema: 'https://abaxx.tech/schemas/dwn/kms-private-key'
        };
    }
    deleteKey(options) {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
            const { agent, context, id } = options;
            // Determine which DID to use to author DWN messages.
            const authorDid = yield this.getAuthor({ agent, context });
            // Query the DWN for all stored key objects.
            const { reply: queryReply } = yield this.getKeyRecords(agent, context);
            // Loop through all of the entries and try to find a match.
            let matchingRecordId;
            for (const record of (_a = queryReply.entries) !== null && _a !== void 0 ? _a : []) {
                // @ts-ignore
                if (record.encodedData) {
                    // @ts-ignore
                    const storedKey = this.decodeKey(record.encodedData);
                    if (storedKey && storedKey.id === id) {
                        matchingRecordId = record.recordId;
                        break;
                    }
                }
            }
            // Return undefined if the specified key was not found in the store.
            if (!matchingRecordId)
                return false;
            // If a record for the specified key was found, attempt to delete it.
            const { reply: { status } } = yield agent.dwnManager.processRequest({
                author: authorDid,
                target: authorDid,
                messageType: 'RecordsDelete',
                messageOptions: {
                    recordId: matchingRecordId
                }
            });
            // If the key was successfully deleted, return true;
            if (status.code === 202)
                return true;
            // If the key could not be deleted, return false;
            return false;
        });
    }
    findKey() {
        return __awaiter(this, void 0, void 0, function* () {
            throw new Error(`PrivateKeyStoreDwn: Method not implemented: 'findKey'`);
        });
    }
    getKey(options) {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
            const { agent, context, id } = options;
            // Query the DWN for all stored key objects.
            const { reply: queryReply } = yield this.getKeyRecords(agent, context);
            // Loop through all of the entries and return a match, if found.
            for (const record of (_a = queryReply.entries) !== null && _a !== void 0 ? _a : []) {
                // @ts-ignore
                if (record.encodedData) {
                    // @ts-ignore
                    const storedKey = this.decodeKey(record.encodedData);
                    if (storedKey.id === id)
                        return storedKey;
                }
            }
            // Return undefined if no matches were found.
            return undefined;
        });
    }
    importKey(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const { agent, context, key } = options;
            if (!key.material)
                throw new TypeError(`Required parameter missing: 'material'`);
            if (!key.type)
                throw new TypeError(`Required parameter missing: 'type'`);
            // Determine which DID to use to author DWN messages.
            const authorDid = yield this.getAuthor({ agent, context });
            // Encode the managed key or key pair as bytes.
            const id = cryptoUtils.randomUuid(); // Generate a random ID.
            const encodedPrivateKey = this.encodeKey(Object.assign(Object.assign({}, key), { id }));
            const { reply: { status } } = yield agent.dwnManager.processRequest({
                author: authorDid,
                target: authorDid,
                messageType: 'RecordsWrite',
                messageOptions: Object.assign({}, this._keyRecordProperties),
                dataStream: new Blob([encodedPrivateKey])
            });
            // If the write fails, throw an error.
            if (status.code !== 202) {
                throw new Error('PrivateKeyStoreDwn: Failed to write imported DID to store.');
            }
            return id;
        });
    }
    listKeys(options) {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
            const { agent, context } = options;
            // Query the DWN for all stored key objects.
            const { reply: queryReply } = yield this.getKeyRecords(agent, context);
            // Loop through all of the entries and accumulate the key objects.
            let storedKeys = [];
            for (const record of (_a = queryReply.entries) !== null && _a !== void 0 ? _a : []) {
                // @ts-ignore
                if (record.encodedData) {
                    // @ts-ignore
                    const storedKey = this.decodeKey(record.encodedData);
                    storedKeys.push(storedKey);
                }
            }
            return storedKeys;
        });
    }
    updateKey() {
        return __awaiter(this, void 0, void 0, function* () {
            throw new Error(`PrivateKeyStoreMemory: Method not implemented: 'updateKey'`);
        });
    }
    decodeKey(keyEncodedData) {
        const encodedKey = Convert.base64Url(keyEncodedData).toObject();
        const privateKey = Object.assign(Object.assign({}, encodedKey), { material: Convert.base64Url(encodedKey.material).toUint8Array() });
        return privateKey;
    }
    encodeKey(privateKey) {
        const encodedKey = Object.assign(Object.assign({}, privateKey), { material: Convert.uint8Array(privateKey.material).toBase64Url() });
        const keyBytes = Convert.object(encodedKey).toUint8Array();
        return keyBytes;
    }
    getAuthor(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const { agent, context } = options;
            // If `context` is specified, DWN messages will be signed by this DID.
            if (context)
                return context;
            // If Agent has an agentDid, use it to sign DWN messages.
            if (agent.agentDid)
                return agent.agentDid;
            // If `context` and `agent.agentDid`are undefined, throw error.
            throw new Error(`PrivateKeyStoreDwn: Agent property 'agentDid' is undefined and no context was specified.`);
        });
    }
    getKeyRecords(agent, context) {
        return __awaiter(this, void 0, void 0, function* () {
            // Determine which DID to use to author DWN messages.
            const authorDid = yield this.getAuthor({ agent, context });
            const dwnResponse = yield agent.dwnManager.processRequest({
                author: authorDid,
                target: authorDid,
                messageType: 'RecordsQuery',
                messageOptions: {
                    filter: Object.assign({}, this._keyRecordProperties)
                }
            });
            return dwnResponse;
        });
    }
}
/**
 * An implementation of `ManagedKeyStore` that stores private key
 * material in memory.
 *
 * An instance of this class can be used by an implementation of
 * `KeyManagementSystem`.
 */
export class PrivateKeyStoreMemory {
    constructor() {
        /**
         * A private field that contains the Map used as the in-memory key-value store.
         */
        this.store = new Map();
    }
    deleteKey({ id }) {
        return __awaiter(this, void 0, void 0, function* () {
            if (this.store.has(id)) {
                // Key with given ID exists so proceed with delete.
                this.store.delete(id);
                return true;
            }
            // Key with given ID not present so delete operation not possible.
            return false;
        });
    }
    findKey() {
        return __awaiter(this, void 0, void 0, function* () {
            throw new Error(`PrivateKeyStoreMemory: Method not implemented: 'findKey'`);
        });
    }
    getKey({ id }) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.store.get(id);
        });
    }
    importKey({ key }) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!key.material)
                throw new TypeError(`Required parameter missing: 'material'`);
            if (!key.type)
                throw new TypeError(`Required parameter missing: 'type'`);
            // Make a deep copy of the key so that the object stored does not share the same references as the input key.
            // The private key material is transferred to the new object, making the original obj.material unusable.
            const clonedKey = structuredClone(key, { transfer: [key.material.buffer] });
            clonedKey.id = cryptoUtils.randomUuid();
            this.store.set(clonedKey.id, clonedKey);
            return clonedKey.id;
        });
    }
    listKeys() {
        return __awaiter(this, void 0, void 0, function* () {
            return Array.from(this.store.values());
        });
    }
    updateKey() {
        return __awaiter(this, void 0, void 0, function* () {
            throw new Error(`PrivateKeyStoreMemory: Method not implemented: 'updateKey'`);
        });
    }
}
//# sourceMappingURL=store-managed-key.js.map