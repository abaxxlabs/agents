"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DidStoreMemory = exports.DidStoreDwn = void 0;
const index_js_1 = require("../common/index.js");
/**
 *
 */
class DidStoreDwn {
    constructor() {
        this._didRecordProperties = {
            dataFormat: 'application/json',
            schema: 'https://abaxx.tech/schemas/dwn/managed-did'
        };
    }
    async deleteDid(options) {
        var _a;
        const { agent, context, did } = options;
        // Determine which DID to use to author DWN messages.
        const authorDid = await this.getAuthor({ agent, context, did });
        // Query the DWN for all stored DID objects.
        const { reply: queryReply } = await agent.dwnManager.processRequest({
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
                const storedDid = index_js_1.Convert.base64Url(record.encodedData).toObject();
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
        const { reply: { status } } = await agent.dwnManager.processRequest({
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
    }
    async findDid(options) {
        var _a;
        const { agent, alias, context, did } = options;
        // Determine which DID to use to author DWN messages.
        const authorDid = await this.getAuthor({ agent, context, did });
        // Query the DWN for all stored DID objects.
        const { reply: queryReply } = await agent.dwnManager.processRequest({
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
                const storedDid = index_js_1.Convert.base64Url(record.encodedData).toObject();
                if (storedDid && storedDid.did === did)
                    return storedDid;
                if (storedDid && storedDid.alias === alias)
                    return storedDid;
            }
        }
        // Return undefined if no matches were found.
        return undefined;
    }
    async getDid(options) {
        var _a;
        const { agent, context, did } = options;
        // Determine which DID to use to author DWN messages.
        const authorDid = await this.getAuthor({ agent, context, did });
        // Query the DWN for all stored DID objects.
        const { reply: queryReply } = await agent.dwnManager.processRequest({
            author: authorDid,
            target: authorDid,
            messageType: 'RecordsQuery',
            messageOptions: { filter: Object.assign({}, this._didRecordProperties) }
        });
        // Loop through all of the entries and return a match, if found.
        for (const record of (_a = queryReply.entries) !== null && _a !== void 0 ? _a : []) {
            if (record.encodedData) {
                const storedDid = index_js_1.Convert.base64Url(record.encodedData).toObject();
                if (storedDid && storedDid.did === did)
                    return storedDid;
            }
        }
        // Return undefined if no matches were found.
        return undefined;
    }
    async importDid(options) {
        const { agent, context, did: importDid } = options;
        // Determine which DID to use to author DWN messages.
        const authorDid = await this.getAuthor({ agent, context, did: importDid.did });
        // Check if the DID being imported is already present in the store.
        const duplicateFound = await this.getDid({ agent, context, did: importDid.did });
        if (duplicateFound) {
            throw new Error(`DidStoreDwn: DID with ID already exists: '${importDid.did}'`);
        }
        // Encode the ManagedDid as bytes.
        const importDidU8A = index_js_1.Convert.object(importDid).toUint8Array();
        const { reply: { status } } = await agent.dwnManager.processRequest({
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
    }
    async listDids(options) {
        var _a;
        const { agent, context } = options;
        // Determine which DID to use to author DWN messages.
        const authorDid = await this.getAuthor({ agent, context });
        // Query the DWN for all stored DID objects.
        const { reply: queryReply } = await agent.dwnManager.processRequest({
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
                const storedDid = index_js_1.Convert.base64Url(record.encodedData).toObject();
                storedDids.push(storedDid);
            }
        }
        return storedDids;
    }
    async getAuthor(options) {
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
        const signingKeyId = await agent.didManager.getDefaultSigningKey({ did });
        const keyPair = (signingKeyId)
            ? await agent.keyManager.getKey({ keyRef: signingKeyId })
            : undefined;
        // If a key pair is found, use the `did` to sign messages.
        if (keyPair)
            return did;
        // If all else fails, throw an error.
        throw new Error(`DidStoreDwn: Agent property 'agentDid' is undefined and no keys were found for: '${did}'`);
    }
}
exports.DidStoreDwn = DidStoreDwn;
/**
 *
 */
class DidStoreMemory {
    constructor() {
        /**
         * A private field that contains the Map used as the in-memory key-value store.
         */
        this.store = new Map();
    }
    async deleteDid({ did }) {
        if (this.store.has(did)) {
            // DID with given identifier exists so proceed with delete.
            this.store.delete(did);
            return true;
        }
        // DID with given identifier not present so delete operation not possible.
        return false;
    }
    async getDid({ did }) {
        return this.store.get(did);
    }
    async findDid(options) {
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
    }
    async importDid(options) {
        const { did: importDid } = options;
        if (this.store.has(importDid.did)) {
            // DID with given identifier already exists so import operation cannot proceed.
            throw new Error(`DidStoreMemory: DID with ID already exists: '${importDid.did}'`);
        }
        // Make a deep copy of the DID so that the object stored does not share the same references as the input.
        const clonedDid = structuredClone(importDid);
        this.store.set(importDid.did, clonedDid);
    }
    async listDids() {
        return Array.from(this.store.values());
    }
}
exports.DidStoreMemory = DidStoreMemory;
//# sourceMappingURL=store-managed-did.js.map