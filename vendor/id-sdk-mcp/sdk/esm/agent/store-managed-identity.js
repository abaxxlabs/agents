var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
//@ts-nocheck
import { Convert } from '../common/index.js';
/**
 *
 */
export class IdentityStoreDwn {
    constructor() {
        this._identityRecordProperties = {
            dataFormat: 'application/json',
            schema: 'https://abaxx.tech/schemas/dwn/managed-identity'
        };
    }
    deleteIdentity(options) {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
            const { agent, context, did } = options;
            // Determine which DID to use to author DWN messages.
            const authorDid = yield this.getAuthor({ agent, context, did });
            // Query the DWN for all stored Identity objects.
            const { reply: queryReply } = yield agent.dwnManager.processRequest({
                author: authorDid,
                target: authorDid,
                messageType: 'RecordsQuery',
                messageOptions: {
                    filter: Object.assign({}, this._identityRecordProperties)
                }
            });
            // Loop through all of the entries and try to find a match.
            let matchingRecordId;
            for (const record of (_a = queryReply.entries) !== null && _a !== void 0 ? _a : []) {
                if (record.encodedData) {
                    const storedIdentity = Convert.base64Url(record.encodedData).toObject();
                    if (storedIdentity && storedIdentity.did === did) {
                        matchingRecordId = record.recordId;
                        break;
                    }
                }
            }
            // Return undefined if the specified Identity was not found in the store.
            if (!matchingRecordId)
                return false;
            // If a record for the specified Identity was found, attempt to delete it.
            const { reply: { status } } = yield agent.dwnManager.processRequest({
                author: authorDid,
                target: authorDid,
                messageType: 'RecordsDelete',
                messageOptions: {
                    recordId: matchingRecordId
                }
            });
            // If the Identity was successfully deleted, return true;
            if (status.code === 202)
                return true;
            // If the Identity could not be deleted, return false;
            return false;
        });
    }
    getIdentity(options) {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
            const { agent, context, did } = options;
            // Determine which DID to use to author DWN messages.
            const authorDid = yield this.getAuthor({ agent, context, did });
            // Query the DWN for all stored Identity objects.
            const { reply: queryReply } = yield agent.dwnManager.processRequest({
                author: authorDid,
                target: authorDid,
                messageType: 'RecordsQuery',
                messageOptions: { filter: Object.assign({}, this._identityRecordProperties) }
            });
            // Loop through all of the entries and return a match, if found.
            for (const record of (_a = queryReply.entries) !== null && _a !== void 0 ? _a : []) {
                if (record.encodedData) {
                    const storedIdentity = Convert.base64Url(record.encodedData).toObject();
                    if (storedIdentity && storedIdentity.did === did)
                        return storedIdentity;
                }
            }
            // Return undefined if no matches were found.
            return undefined;
        });
    }
    importIdentity(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const { agent, context, identity } = options;
            // Determine which DID to use to author DWN messages.
            const authorDid = yield this.getAuthor({ agent, context, did: identity.did });
            // Check if the Identity being imported is already present in the store.
            const duplicateFound = yield this.getIdentity({ agent, context, did: identity.did });
            if (duplicateFound) {
                throw new Error(`IdentityStoreDwn: Identity with DID already exists: '${identity.did}'`);
            }
            // Encode the ManagedIdentity as bytes.
            const identityU8A = Convert.object(identity).toUint8Array();
            const { reply: { status } } = yield agent.dwnManager.processRequest({
                author: authorDid,
                target: authorDid,
                messageType: 'RecordsWrite',
                messageOptions: Object.assign({}, this._identityRecordProperties),
                dataStream: new Blob([identityU8A])
            });
            // If the write fails, throw an error.
            if (status.code !== 202) {
                throw new Error('IdentityStoreDwn: Failed to write imported identity to store.');
            }
        });
    }
    listIdentities(options) {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
            const { agent, context } = options;
            // Determine which DID to use to author DWN messages.
            const authorDid = yield this.getAuthor({ agent, context });
            // Query the DWN for all stored Identity objects.
            const { reply: queryReply } = yield agent.dwnManager.processRequest({
                author: authorDid,
                target: authorDid,
                messageType: 'RecordsQuery',
                messageOptions: {
                    filter: Object.assign({}, this._identityRecordProperties)
                }
            });
            // Loop through all of the entries and accumulate the Identity objects.
            let storedIdentities = [];
            for (const record of (_a = queryReply.entries) !== null && _a !== void 0 ? _a : []) {
                if (record.encodedData) {
                    const storedIdentity = Convert.base64Url(record.encodedData).toObject();
                    storedIdentities.push(storedIdentity);
                }
            }
            return storedIdentities;
        });
    }
    getAuthor(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const { context, did, agent } = options;
            // If `context` is specified, DWN messages will be signed by this DID.
            if (context)
                return context;
            // If Agent has an agentDid, use it to sign DWN messages.
            if (agent.agentDid)
                return agent.agentDid;
            // If `context`, `agent.agentDid`, and `did` are undefined, throw error.
            if (!did) {
                throw new Error(`DidStoreDwn: Agent property 'agentDid' is undefined.`);
            }
            /** Lacking a context and agentDid DID, check whether KeyManager has
             * a key pair for the given `did` value.*/
            const signingKeyId = yield agent.didManager.getDefaultSigningKey({ did });
            const keyPair = (signingKeyId)
                ? yield agent.keyManager.getKey({ keyRef: signingKeyId })
                : undefined;
            // If a key pair is found, use the `did` to sign messages.
            if (keyPair)
                return did;
            // If all else fails, throw an error.
            throw new Error(`IdentityStoreDwn: Agent property 'agentDid' is undefined and no keys were found for: '${did}'`);
        });
    }
}
/**
 *
 */
export class IdentityStoreMemory {
    constructor() {
        /**
         * A private field that contains the Map used as the in-memory key-value store.
         */
        this.store = new Map();
    }
    deleteIdentity({ did }) {
        return __awaiter(this, void 0, void 0, function* () {
            if (this.store.has(did)) {
                // Identity with given DID exists so proceed with delete.
                this.store.delete(did);
                return true;
            }
            // Identity with given DID not present so delete operation not possible.
            return false;
        });
    }
    getIdentity({ did }) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.store.get(did);
        });
    }
    importIdentity(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const { identity } = options;
            if (this.store.has(identity.did)) {
                // Identity with given identifier already exists so import operation cannot proceed.
                throw new Error(`IdentityStoreMemory: Identity with DID already exists: '${identity.did}'`);
            }
            // Make a deep copy of the Identity so that the object stored does not share the same references as the input.
            const clonedIdentity = structuredClone(identity);
            this.store.set(identity.did, clonedIdentity);
        });
    }
    listIdentities() {
        return __awaiter(this, void 0, void 0, function* () {
            return Array.from(this.store.values());
        });
    }
}
//# sourceMappingURL=store-managed-identity.js.map