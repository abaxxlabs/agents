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
exports.DwnApi = void 0;
const index_js_1 = require("./common/index.js");
const id_1 = require("@abaxxtech/id");
const record_js_1 = require("./record.js");
const protocol_js_1 = require("./protocol.js");
const utils_js_1 = require("./utils.js");
const service_options_js_1 = require("./service-options.js");
/**
 * Interface to interact with DWN Records and Protocols
 *
 * @beta
 */
class DwnApi {
    constructor(options) {
        this.agent = options.agent;
        this.connectedDid = options.connectedDid;
    }
    /**
    * API to interact with DWN protocols (e.g., `dwn.protocols.configure()`).
    */
    get protocols() {
        return {
            /**
             * Configure method, used to setup a new protocol (or update) with the passed definitions
             */
            configure: async (request) => {
                const agentResponse = await this.agent.processDwnRequest({
                    target: this.connectedDid,
                    author: this.connectedDid,
                    messageOptions: request.message,
                    messageType: id_1.DwnInterfaceName.Protocols + id_1.DwnMethodName.Configure
                });
                const { message, messageCid, reply: { status } } = agentResponse;
                const response = { status };
                if (status.code < 300) {
                    const metadata = { author: this.connectedDid, messageCid };
                    response.protocol = new protocol_js_1.Protocol(this.agent, message, metadata);
                }
                return response;
            },
            /**
             * Query the available protocols
             */
            query: async (request) => {
                const agentRequest = {
                    author: this.connectedDid,
                    messageOptions: request.message,
                    messageType: id_1.DwnInterfaceName.Protocols + id_1.DwnMethodName.Query,
                    target: request.from || this.connectedDid
                };
                let agentResponse;
                if (request.from) {
                    agentResponse = await this.agent.sendDwnRequest(agentRequest);
                }
                else {
                    agentResponse = await this.agent.processDwnRequest(agentRequest);
                }
                const { reply: { entries = [], status } } = agentResponse;
                const protocols = entries.map((entry) => {
                    const metadata = { author: this.connectedDid, };
                    //@ts-ignore
                    return new protocol_js_1.Protocol(this.agent, entry, metadata);
                    // @todo fix the type, then remove `as ProtocolsConfigureMessage ^
                });
                return { protocols, status };
            }
        };
    }
    /**
     * API to interact with DWN records (e.g., `dwn.records.create()`).
     */
    get records() {
        return {
            /**
             * Alias for the `write` method
             */
            create: async (request) => {
                return this.records.write(request);
            },
            /**
             * Write a record based on an existing one (useful for updating an existing record)
             */
            createFrom: async (request) => {
                var _a;
                const _b = request.record.toJSON(), { author: inheritedAuthor } = _b, inheritedProperties = __rest(_b, ["author"]);
                // Remove target from inherited properties since target is being explicitly defined in method parameters.
                delete inheritedProperties.target;
                // If `data` is being updated then `dataCid` and `dataSize` must not be present.
                if (request.data !== undefined) {
                    delete inheritedProperties.dataCid;
                    delete inheritedProperties.dataSize;
                }
                // Ensure update gets a new messageTimestamp so it's always "newer" than the original.
                // Mirrors @abaxxtech/id RecordsWrite.createFrom behavior.
                delete inheritedProperties.messageTimestamp;
                // If `published` is set to false, ensure that `datePublished` is undefined. Otherwise, DWN SDK's schema validation
                // will throw an error if `published` is false but `datePublished` is set.
                if (((_a = request.message) === null || _a === void 0 ? void 0 : _a.published) === false && inheritedProperties.datePublished !== undefined) {
                    delete inheritedProperties.datePublished;
                    delete inheritedProperties.published;
                }
                // If the request changes the `author` or message `descriptor` then the deterministic `recordId` will change.
                // As a result, we will discard the `recordId` if either of these changes occur.
                // NOTE: `isEmptyObject(undefined)` returns false, so we must guard against undefined/null
                // to avoid discarding `recordId` when no message overrides are provided (update case).
                const hasMessageOverrides = request.message != null && !(0, index_js_1.isEmptyObject)(request.message);
                const hasAuthorChange = request.author && request.author !== inheritedAuthor;
                if (hasMessageOverrides || hasAuthorChange) {
                    delete inheritedProperties.recordId;
                }
                return this.records.write({
                    data: request.data,
                    target: request.target,
                    message: Object.assign(Object.assign({}, inheritedProperties), request.message),
                });
            },
            /**
             * Delete a record
             */
            delete: async (request) => {
                const agentRequest = {
                    author: this.connectedDid,
                    messageOptions: request.message,
                    messageType: id_1.DwnInterfaceName.Records + id_1.DwnMethodName.Delete,
                    target: request.from || this.connectedDid
                };
                let agentResponse;
                if (request.from) {
                    agentResponse = await this.agent.sendDwnRequest(agentRequest);
                }
                else {
                    agentResponse = await this.agent.processDwnRequest(agentRequest);
                }
                const { reply: { status } } = agentResponse;
                return { status };
            },
            /**
             * Query a single or multiple records based on the given filter
             */
            query: async (request) => {
                const agentRequest = {
                    author: this.connectedDid,
                    messageOptions: request.message,
                    messageType: id_1.DwnInterfaceName.Records + id_1.DwnMethodName.Query,
                    target: request.from || this.connectedDid
                };
                let agentResponse;
                if (request.from) {
                    agentResponse = await this.agent.sendDwnRequest(agentRequest);
                }
                else {
                    agentResponse = await this.agent.processDwnRequest(agentRequest);
                }
                const { reply: { entries, status, cursor } } = agentResponse;
                const records = entries.map((entry) => {
                    const recordOptions = Object.assign({ 
                        /**
                         * Extract the `author` DID from the record entry since records may be signed by the
                         * tenant owner or any other entity.
                         */
                        author: id_1.RecordsWrite.getAuthor(entry), 
                        /**
                         * Set the `target` DID to currently connected DID so that subsequent calls to
                         * {@link Record} instance methods, such as `record.update()` are executed on the
                         * local DWN even if the record was returned by a query of a remote DWN.
                         */
                        target: this.connectedDid }, entry);
                    const record = new record_js_1.Record(this.agent, recordOptions);
                    return record;
                });
                return { records, status, cursor };
            },
            /**
             * Read a single record based on the given filter
             */
            read: async (request) => {
                const agentRequest = {
                    author: this.connectedDid,
                    messageOptions: request.message,
                    messageType: id_1.DwnInterfaceName.Records + id_1.DwnMethodName.Read,
                    target: request.from || this.connectedDid
                };
                let agentResponse;
                if (request.from) {
                    agentResponse = await this.agent.sendDwnRequest(agentRequest);
                }
                else {
                    agentResponse = await this.agent.processDwnRequest(agentRequest);
                }
                const { reply: { record: responseRecord, status } } = agentResponse;
                let record;
                if (200 <= status.code && status.code <= 299) {
                    const recordOptions = Object.assign({ author: id_1.RecordsWrite.getAuthor(responseRecord), target: this.connectedDid }, responseRecord);
                    record = new record_js_1.Record(this.agent, recordOptions);
                }
                return { record, status };
            },
            /**
             * Writes a record to the DWN
             *
             * As a convenience, the Record instance returned will cache a copy of the data if the
             * data size, in bytes, is less than the DWN 'max data size allowed to be encoded'
             * parameter of 10KB. This is done to maintain consistency with other DWN methods,
             * like RecordsQuery, that include relatively small data payloads when returning
             * RecordsWrite message properties. Regardless of data size, methods such as
             * `record.data.stream()` will return the data when called even if it requires fetching
             * from the DWN datastore.
             */
            write: async (request) => {
                const messageOptions = Object.assign({}, request.message);
                const { dataBlob, dataFormat } = (0, utils_js_1.dataToBlob)(request.data, messageOptions.dataFormat);
                messageOptions.dataFormat = dataFormat;
                const target = request.target || this.connectedDid;
                const isRemote = target !== this.connectedDid;
                let agentResponse;
                if (isRemote) {
                    agentResponse = await this.agent.sendDwnRequest({
                        author: this.connectedDid,
                        dataStream: dataBlob,
                        messageOptions,
                        messageType: id_1.DwnInterfaceName.Records + id_1.DwnMethodName.Write,
                        target: target
                    });
                }
                else {
                    agentResponse = await this.agent.processDwnRequest({
                        author: this.connectedDid,
                        dataStream: dataBlob,
                        messageOptions,
                        messageType: id_1.DwnInterfaceName.Records + id_1.DwnMethodName.Write,
                        store: request.store,
                        target: this.connectedDid
                    });
                }
                const { message, reply: { status } } = agentResponse;
                const responseMessage = message;
                let record;
                if (200 <= status.code && status.code <= 299) {
                    const recordOptions = Object.assign({ author: this.connectedDid, encodedData: dataBlob, target: target }, responseMessage);
                    record = new record_js_1.Record(this.agent, recordOptions);
                }
                return { record, status };
            },
        };
    }
    /**
     * API to retrieve the service nodes via did:web:dwn.x.id.
     */
    async getServiceNodes() {
        return await (0, service_options_js_1.getServiceDwnEndpoints)();
    }
    /**
     * Helper method to resolve encryption keys from a recipient's DID.
     * This can be used to get encryption keys before creating an encrypted RecordsWrite.
     *
     * @param recipientDid - The DID of the recipient
     * @param options - Optional configuration
     * @param options.useRelayEndpoint - If true, uses the relay's /api/did/:did/encryption-keys endpoint (default: false)
     * @param options.relayUrl - The relay URL to use (default: tries to detect from service endpoints)
     * @returns Array of encryption keys with keyId, publicKeyJwk, and keyType
     */
    async resolveRecipientEncryptionKeys(recipientDid, options) {
        var _a, _b;
        const { useRelayEndpoint = false, relayUrl } = options || {};
        // Option 1: Use relay endpoint if specified
        if (useRelayEndpoint) {
            try {
                const url = relayUrl || (await (0, service_options_js_1.getServiceDwnEndpoints)())[0] || 'http://localhost:8085';
                const response = await fetch(`${url}/api/did/${recipientDid}/encryption-keys`);
                const result = await response.json();
                if (result.ok && result.encryptionKeys) {
                    return result.encryptionKeys;
                }
            }
            catch (error) {
                console.warn('Failed to resolve encryption keys via relay endpoint:', error);
            }
        }
        // Option 2: Use SDK's built-in DID resolver
        try {
            // Check if agent has didResolver (IDManagedAgent)
            const managedAgent = this.agent;
            if (!managedAgent.didResolver) {
                throw new Error('DID resolver not available. Use useRelayEndpoint: true or ensure agent is properly initialized.');
            }
            const { didDocument } = await managedAgent.didResolver.resolve(recipientDid);
            if (!didDocument) {
                throw new Error(`DID document not found for ${recipientDid}`);
            }
            const encryptionKeys = [];
            // Look for verification methods with publicKeyJwk
            if (didDocument.verificationMethod) {
                for (const vm of didDocument.verificationMethod) {
                    if (vm.publicKeyJwk && vm.id) {
                        const keyId = vm.id.includes('#') ? vm.id.split('#')[1] : vm.id;
                        if (keyId) {
                            encryptionKeys.push({
                                keyId,
                                publicKeyJwk: vm.publicKeyJwk,
                                keyType: vm.type || 'Unknown',
                            });
                        }
                    }
                }
            }
            // Also check keyAgreement section
            if (didDocument.keyAgreement) {
                for (const ka of didDocument.keyAgreement) {
                    if (typeof ka === 'string') {
                        const keyId = ka.includes('#') ? ka.split('#')[1] : ka;
                        const vm = (_a = didDocument.verificationMethod) === null || _a === void 0 ? void 0 : _a.find((v) => v.id === ka || v.id.endsWith(`#${keyId}`));
                        if ((vm === null || vm === void 0 ? void 0 : vm.publicKeyJwk) && keyId) {
                            encryptionKeys.push({
                                keyId,
                                publicKeyJwk: vm.publicKeyJwk,
                                keyType: vm.type || 'Unknown',
                            });
                        }
                    }
                    else if (ka.publicKeyJwk) {
                        const keyId = ((_b = ka.id) === null || _b === void 0 ? void 0 : _b.includes('#'))
                            ? ka.id.split('#')[1]
                            : ka.id || 'unknown';
                        if (keyId) {
                            encryptionKeys.push({
                                keyId,
                                publicKeyJwk: ka.publicKeyJwk,
                                keyType: ka.type || 'Unknown',
                            });
                        }
                    }
                }
            }
            return encryptionKeys;
        }
        catch (error) {
            throw new Error(`Failed to resolve encryption keys for ${recipientDid}: ${error.message}`);
        }
    }
}
exports.DwnApi = DwnApi;
//# sourceMappingURL=dwn-api.js.map