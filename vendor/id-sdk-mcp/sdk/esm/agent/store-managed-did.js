var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { Convert } from '../common/index.js';
/**
 *
 */
export class DidStoreDwn {
    constructor() {
        this._didRecordProperties = {
            dataFormat: 'application/json',
            schema: 'https://abaxx.tech/schemas/dwn/managed-did'
        };
    }
    deleteDid(options) {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
            const { agent, context, did } = options;
            // Determine which DID to use to author DWN messages.
            const authorDid = yield this.getAuthor({ agent, context, did });
            // Query the DWN for all stored DID objects.
            const { reply: queryReply } = yield agent.dwnManager.processRequest({
                author: authorDid,
                target: authorDid,
                messageType: 'RecordsQuery',
                messageOptions: {
                    filter: Object.assign({}, this._didRecordProperties)
                }
            });
            // Loop through all of the entries and try to find a match.
            let matchingRecordId;
            for (const record of (_a = queryReply.entries) !== null && _a !== void 0 ? _a : []) {
                if (record.encodedData) {
                    const storedDid = Convert.base64Url(record.encodedData).toObject();
                    if (storedDid && storedDid.did === did) {
                        matchingRecordId = record.recordId;
                        break;
                    }
                }
            }
            // Return undefined if the specified DID was not found in the store.
            if (!matchingRecordId)
                return false;
            // If a record for the specified DID was found, attempt to delete it.
            const { reply: { status } } = yield agent.dwnManager.processRequest({
                author: authorDid,
                target: authorDid,
                messageType: 'RecordsDelete',
                messageOptions: {
                    recordId: matchingRecordId
                }
            });
            // If the DID was successfully deleted, return true;
            if (status.code === 202)
                return true;
            // If the DID could not be deleted, return false;
            return false;
        });
    }
    findDid(options) {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
            const { agent, alias, context, did } = options;
            // Determine which DID to use to author DWN messages.
            const authorDid = yield this.getAuthor({ agent, context, did });
            // Query the DWN for all stored DID objects.
            const { reply: queryReply } = yield agent.dwnManager.processRequest({
                author: authorDid,
                target: authorDid,
                messageType: 'RecordsQuery',
                messageOptions: {
                    filter: Object.assign({}, this._didRecordProperties)
                }
            });
            // Loop through all of the entries and return a match, if found.
            for (const record of (_a = queryReply.entries) !== null && _a !== void 0 ? _a : []) {
                if (record.encodedData) {
                    const storedDid = Convert.base64Url(record.encodedData).toObject();
                    if (storedDid && storedDid.did === did)
                        return storedDid;
                    if (storedDid && storedDid.alias === alias)
                        return storedDid;
                }
            }
            // Return undefined if no matches were found.
            return undefined;
        });
    }
    getDid(options) {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
            const { agent, context, did } = options;
            // Determine which DID to use to author DWN messages.
            const authorDid = yield this.getAuthor({ agent, context, did });
            // Query the DWN for all stored DID objects.
            const { reply: queryReply } = yield agent.dwnManager.processRequest({
                author: authorDid,
                target: authorDid,
                messageType: 'RecordsQuery',
                messageOptions: { filter: Object.assign({}, this._didRecordProperties) }
            });
            // Loop through all of the entries and return a match, if found.
            for (const record of (_a = queryReply.entries) !== null && _a !== void 0 ? _a : []) {
                if (record.encodedData) {
                    const storedDid = Convert.base64Url(record.encodedData).toObject();
                    if (storedDid && storedDid.did === did)
                        return storedDid;
                }
            }
            // Return undefined if no matches were found.
            return undefined;
        });
    }
    importDid(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const { agent, context, did: importDid } = options;
            // Determine which DID to use to author DWN messages.
            const authorDid = yield this.getAuthor({ agent, context, did: importDid.did });
            // Check if the DID being imported is already present in the store.
            const duplicateFound = yield this.getDid({ agent, context, did: importDid.did });
            if (duplicateFound) {
                throw new Error(`DidStoreDwn: DID with ID already exists: '${importDid.did}'`);
            }
            // Encode the ManagedDid as bytes.
            const importDidU8A = Convert.object(importDid).toUint8Array();
            const { reply: { status } } = yield agent.dwnManager.processRequest({
                author: authorDid,
                target: authorDid,
                messageType: 'RecordsWrite',
                messageOptions: Object.assign({}, this._didRecordProperties),
                dataStream: new Blob([importDidU8A])
            });
            // If the write fails, throw an error.
            if (status.code !== 202) {
                throw new Error('DidStoreDwn: Failed to write imported DID to store.');
            }
        });
    }
    listDids(options) {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
            const { agent, context } = options;
            // Determine which DID to use to author DWN messages.
            const authorDid = yield this.getAuthor({ agent, context });
            // Query the DWN for all stored DID objects.
            const { reply: queryReply } = yield agent.dwnManager.processRequest({
                author: authorDid,
                target: authorDid,
                messageType: 'RecordsQuery',
                messageOptions: {
                    filter: Object.assign({}, this._didRecordProperties)
                }
            });
            // Loop through all of the entries and accumulate the DID objects.
            let storedDids = [];
            for (const record of (_a = queryReply.entries) !== null && _a !== void 0 ? _a : []) {
                if (record.encodedData) {
                    const storedDid = Convert.base64Url(record.encodedData).toObject();
                    storedDids.push(storedDid);
                }
            }
            return storedDids;
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
            throw new Error(`DidStoreDwn: Agent property 'agentDid' is undefined and no keys were found for: '${did}'`);
        });
    }
}
/**
 *
 */
export class DidStoreMemory {
    constructor() {
        /**
         * A private field that contains the Map used as the in-memory key-value store.
         */
        this.store = new Map();
    }
    deleteDid({ did }) {
        return __awaiter(this, void 0, void 0, function* () {
            if (this.store.has(did)) {
                // DID with given identifier exists so proceed with delete.
                this.store.delete(did);
                return true;
            }
            // DID with given identifier not present so delete operation not possible.
            return false;
        });
    }
    getDid({ did }) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.store.get(did);
        });
    }
    findDid(options) {
        return __awaiter(this, void 0, void 0, function* () {
            let { alias, did } = options;
            // Get DID by identifier.
            if (did)
                return this.store.get(did);
            if (alias) {
                // Search through the store to find a matching entry
                for (const did of this.store.values()) {
                    if (did.alias === alias)
                        return did;
                }
            }
            return undefined;
        });
    }
    importDid(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const { did: importDid } = options;
            if (this.store.has(importDid.did)) {
                // DID with given identifier already exists so import operation cannot proceed.
                throw new Error(`DidStoreMemory: DID with ID already exists: '${importDid.did}'`);
            }
            // Make a deep copy of the DID so that the object stored does not share the same references as the input.
            const clonedDid = structuredClone(importDid);
            this.store.set(importDid.did, clonedDid);
        });
    }
    listDids() {
        return __awaiter(this, void 0, void 0, function* () {
            return Array.from(this.store.values());
        });
    }
}
//# sourceMappingURL=store-managed-did.js.map