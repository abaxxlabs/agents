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
exports.DwnManager = void 0;
const id_1 = require("@dwn-protocol/id");
const index_js_1 = require("../common/index.js");
const index_js_2 = require("../crypto/index.js");
const didUtils = __importStar(require("../dids/utils.js"));
const id_2 = require("@dwn-protocol/id");
const utils_js_1 = require("./utils.js");
const utils_js_2 = require("./utils.js");
const dwnMessageCreators = {
    [id_2.DwnInterfaceName.Events + id_2.DwnMethodName.Get]: id_2.EventsGet,
    [id_2.DwnInterfaceName.Messages + id_2.DwnMethodName.Get]: id_2.MessagesGet,
    [id_2.DwnInterfaceName.Records + id_2.DwnMethodName.Read]: id_2.RecordsRead,
    [id_2.DwnInterfaceName.Records + id_2.DwnMethodName.Query]: id_2.RecordsQuery,
    [id_2.DwnInterfaceName.Records + id_2.DwnMethodName.Write]: id_2.RecordsWrite,
    [id_2.DwnInterfaceName.Records + id_2.DwnMethodName.Delete]: id_2.RecordsDelete,
    [id_2.DwnInterfaceName.Protocols + id_2.DwnMethodName.Query]: id_2.ProtocolsQuery,
    [id_2.DwnInterfaceName.Protocols + id_2.DwnMethodName.Configure]: id_2.ProtocolsConfigure,
};
class DwnManager {
    constructor(options) {
        this._agent = options.agent;
        this._dwn = options.dwn;
    }
    /**
     * Constructs a Signer for the connected did.
     *
     * @param author - The DID.
     * @returns A promise that resolves to the result.
     */
    async getSigner(author) {
        const signingKeyId = await this.getAuthorSigningKeyId({ did: author });
        const parsedDid = didUtils.parseDid({ didUrl: signingKeyId });
        if (!parsedDid)
            throw new Error(`DidIonMethod: Unable to parse DID: ${signingKeyId}`);
        const normalizedDid = parsedDid.did.split(':', 3).join(':');
        const normalizedSigningKeyId = `${normalizedDid}#${parsedDid.fragment}`;
        const signingKey = await this.agent.keyManager.getKey({ keyRef: normalizedSigningKeyId });
        if (!(0, utils_js_1.isManagedKeyPair)(signingKey)) {
            throw new Error(`DwnManager: Signing key not found for author: '${author}'`);
        }
        const { alg } = index_js_2.Jose.webCryptoToJose(signingKey.privateKey.algorithm);
        if (alg === undefined) {
            throw Error(`No algorithm provided to sign with key ID ${signingKeyId}`);
        }
        return {
            keyId: signingKeyId,
            algorithm: alg,
            sign: async (content) => {
                return await this.agent.keyManager.sign({
                    algorithm: signingKey.privateKey.algorithm,
                    data: content,
                    keyRef: normalizedSigningKeyId
                });
            },
        };
    }
    /**
     * Constructs a Private Key Signer for a did.
     *
     * @param author - The DID Object.
     * @returns A promise that resolves to the result.
     */
    async getPrivateKeySigner(author) {
        const signingKeyId = await this.agent.didManager.getDefaultSigningKey({ did: author.did });
        const signingKeyPair = author.keySet.verificationMethodKeys[0];
        // const signingKeyPair = ionDid.keySet.verificationMethodKeys.find(keyPair => keyPair.publicKeyJwk.kid === "#dwn-sig");
        const signingPrivateKeyJwk = signingKeyPair.privateKeyJwk;
        return [new id_1.PrivateKeySigner({
                privateJwk: signingPrivateKeyJwk,
                algorithm: signingPrivateKeyJwk.alg,
                keyId: signingKeyId,
            })];
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
    get dwn() {
        return this._dwn;
    }
    static async create(options) {
        let { agent, dataPath, didResolver, dwn } = options !== null && options !== void 0 ? options : {};
        dataPath !== null && dataPath !== void 0 ? dataPath : (dataPath = 'DATA/AGENT');
        if (dwn === undefined) {
            // Use LevelDB stores (browser-compatible)
            const dataStore = new id_2.DataStoreLevel({
                blockstoreLocation: `${dataPath}/DWN_DATASTORE`
            });
            const eventLog = new id_2.EventLogLevel({
                location: `${dataPath}/DWN_EVENTLOG`
            });
            const messageStore = new id_2.MessageStoreLevel(({
                blockstoreLocation: `${dataPath}/DWN_MESSAGESTORE`,
                indexLocation: `${dataPath}/DWN_MESSAGEINDEX`
            }));
            // Note: PostgreSQL stores commented out - use environment variable or config to enable
            // const messageStore = new MessageStoreSql(postgresDialect);
            // const dataStore = new DataStoreSql(postgresDialect);
            // const eventLog = new EventLogSql(postgresDialect);
            dwn = await id_2.Dwn.create({
                dataStore,
                //@ts-ignore
                didResolver,
                eventLog,
                messageStore,
            });
        }
        return new DwnManager({ agent, dwn });
    }
    async processRequest(request) {
        const { message, dataStream } = await this.constructDwnMessage({ request });
        let reply;
        if (request.store !== false) {
            // @ts-ignore
            reply = await this._dwn.processMessage(request.target, message, dataStream);
        }
        else {
            reply = { status: { code: 202, detail: 'Accepted' } };
        }
        return {
            reply,
            message: message,
            messageCid: await id_2.Message.getCid(message)
        };
    }
    async sendRequest(request) {
        var _a;
        const dwnRpcRequest = { targetDid: request.target };
        let messageData;
        if ('messageCid' in request) {
            const { message, data } = await this.getDwnMessage({
                author: request.author,
                messageCid: request.messageCid,
                messageType: request.messageType
            });
            dwnRpcRequest.message = message;
            messageData = data;
        }
        else {
            const { message } = await this.constructDwnMessage({ request });
            dwnRpcRequest.message = message;
            messageData = request.dataStream;
        }
        if (messageData) {
            dwnRpcRequest.data = messageData;
        }
        const { didDocument, didResolutionMetadata } = await this.agent.didResolver.resolve(request.target);
        if (!didDocument) {
            const errorCode = `${didResolutionMetadata === null || didResolutionMetadata === void 0 ? void 0 : didResolutionMetadata.error}: ` || '';
            const defaultMessage = `Unable to resolve target DID: ${request.target}`;
            const errorMessage = (_a = didResolutionMetadata === null || didResolutionMetadata === void 0 ? void 0 : didResolutionMetadata.errorMessage) !== null && _a !== void 0 ? _a : defaultMessage;
            throw new Error(`DwnManager: ${errorCode}${errorMessage}`);
        }
        const [service] = didUtils.getServices({ didDocument, id: '#dwn' });
        if (!service) {
            throw new Error(`DwnManager: DID Document of '${request.target}' has no service endpoints with ID '#dwn'`);
        }
        if (!didUtils.isDwnServiceEndpoint(service.serviceEndpoint)) {
            throw new Error(`DwnManager: Malformed '#dwn' service endpoint. Expected array of node addresses.`);
        }
        const dwnEndpointUrls = service.serviceEndpoint.nodes;
        let dwnReply;
        let errorMessages = [];
        // try sending to author's publicly addressable dwn's until first request succeeds.
        for (let dwnUrl of dwnEndpointUrls) {
            dwnRpcRequest.dwnUrl = dwnUrl;
            try {
                dwnReply = await this.agent.rpcClient.sendDwnRequest(dwnRpcRequest);
                break;
            }
            catch (error) {
                const message = (error instanceof Error) ? error.message : 'Unknown error';
                errorMessages.push({ url: dwnUrl, message });
            }
        }
        if (!dwnReply) {
            if (this.agent.outbox) {
                const dataBase64 = messageData
                    ? await this.messageDataToBase64(messageData)
                    : undefined;
                await this.agent.outbox.enqueue(Object.assign({ targetDid: request.target, dwnUrls: dwnEndpointUrls, message: dwnRpcRequest.message }, (dataBase64 !== undefined && { dataBase64 })));
                return {
                    message: dwnRpcRequest.message,
                    messageCid: await id_2.Message.getCid(dwnRpcRequest.message),
                    reply: { status: { code: 202, detail: 'Queued for delivery when online' } },
                };
            }
            throw new Error(JSON.stringify(errorMessages));
        }
        return {
            message: dwnRpcRequest.message,
            messageCid: await id_2.Message.getCid(dwnRpcRequest.message),
            reply: dwnReply,
        };
    }
    async messageDataToBase64(data) {
        if (data instanceof Blob) {
            const u8a = new Uint8Array(await data.arrayBuffer());
            return index_js_1.Convert.uint8Array(u8a).toBase64Url();
        }
        const u8a = await index_js_1.Convert.asyncIterable(data).toUint8ArrayAsync();
        return index_js_1.Convert.uint8Array(u8a).toBase64Url();
    }
    async constructDwnMessage(options) {
        var _a;
        const { request } = options;
        let readableStream;
        if (request.messageType === 'RecordsWrite') {
            const messageOptions = request.messageOptions;
            if (request.dataStream && !messageOptions.data) {
                const { dataStream } = request;
                let isomorphicNodeReadable;
                if (dataStream instanceof Blob) {
                    isomorphicNodeReadable = (0, utils_js_2.blobToIsomorphicNodeReadable)(dataStream);
                    readableStream = (0, utils_js_2.blobToIsomorphicNodeReadable)(dataStream);
                }
                else if (dataStream instanceof ReadableStream) {
                    const [forCid, forProcessMessage] = dataStream.tee();
                    isomorphicNodeReadable = (0, utils_js_2.webReadableToIsomorphicNodeReadable)(forCid);
                    readableStream = (0, utils_js_2.webReadableToIsomorphicNodeReadable)(forProcessMessage);
                }
                // @ts-ignore
                messageOptions.dataCid = await id_2.Cid.computeDagPbCidFromStream(isomorphicNodeReadable);
                // @ts-ignore
                (_a = messageOptions.dataSize) !== null && _a !== void 0 ? _a : (messageOptions.dataSize = isomorphicNodeReadable['bytesRead']);
            }
        }
        const dwnSigner = await this.constructDwnSigner(request.author);
        const messageCreator = dwnMessageCreators[request.messageType];
        const dwnMessage = await messageCreator.create(Object.assign(Object.assign({}, request.messageOptions), { signer: dwnSigner }));
        // return { message: dwnMessage.toJSON(), dataStream: readableStream };
        return { message: dwnMessage.message, dataStream: readableStream };
    }
    async getAuthorSigningKeyId(options) {
        const { did } = options;
        // Get the method-specific default signing key.
        const signingKeyId = await this.agent.didManager.getDefaultSigningKey({ did });
        if (!signingKeyId) {
            throw new Error(`DwnManager: Unable to determine signing key for author: '${did}'`);
        }
        return signingKeyId;
    }
    async constructDwnSigner(author) {
        const signingKeyId = await this.getAuthorSigningKeyId({ did: author });
        /**
         * DID keys stored in KeyManager use the canonicalId as an alias, so
         * normalize the signing key ID before attempting to retrieve the key.
         */
        const parsedDid = didUtils.parseDid({ didUrl: signingKeyId });
        if (!parsedDid)
            throw new Error(`DidIonMethod: Unable to parse DID: ${signingKeyId}`);
        const normalizedDid = parsedDid.did.split(':', 3).join(':');
        const normalizedSigningKeyId = `${normalizedDid}#${parsedDid.fragment}`;
        const signingKey = await this.agent.keyManager.getKey({ keyRef: normalizedSigningKeyId });
        if (!(0, utils_js_1.isManagedKeyPair)(signingKey)) {
            throw new Error(`DwnManager: Signing key not found for author: '${author}'`);
        }
        const { alg } = index_js_2.Jose.webCryptoToJose(signingKey.privateKey.algorithm);
        if (alg === undefined) {
            throw Error(`No algorithm provided to sign with key ID ${signingKeyId}`);
        }
        return {
            keyId: signingKeyId,
            algorithm: alg,
            sign: async (content) => {
                return await this.agent.keyManager.sign({
                    algorithm: signingKey.privateKey.algorithm,
                    data: content,
                    keyRef: normalizedSigningKeyId
                });
            }
        };
    }
    async getDwnMessage(options) {
        const { author, messageType, messageCid } = options;
        const dwnSigner = await this.constructDwnSigner(author);
        const messagesGet = await id_2.MessagesGet.create({
            messageCids: [messageCid],
            signer: dwnSigner
        });
        const result = await this._dwn.processMessage(author, messagesGet.message);
        // @ts-ignore
        if (!(result.messages && result.messages.length === 1)) {
            throw new Error('TODO: message not found');
        }
        // @ts-ignore
        const [messageEntry] = result.messages;
        let { message } = messageEntry;
        if (!message) {
            throw new Error('TODO: message not found');
        }
        let dwnMessage = { message };
        /** If the message is a RecordsWrite, either data will be present, OR
         * we have to fetch it using a RecordsRead. */
        if (messageType === 'RecordsWrite') {
            const { encodedData } = messageEntry;
            const writeMessage = message;
            if (encodedData) {
                const dataBytes = index_js_1.Convert.base64Url(encodedData).toUint8Array();
                dwnMessage.data = new Blob([dataBytes]);
            }
            else {
                const recordsRead = await id_2.RecordsRead.create({
                    filter: {
                        recordId: writeMessage.recordId
                    },
                    signer: dwnSigner
                });
                const reply = await this._dwn.processMessage(author, recordsRead.message);
                if (reply.status.code >= 400) {
                    const { status: { code, detail } } = reply;
                    throw new Error(`(${code}) Failed to read data associated with record ${writeMessage.recordId}. ${detail}}`);
                }
                else if (reply.record) {
                    const dataBytes = await id_2.DataStream.toBytes(reply.record.data);
                    dwnMessage.data = new Blob([dataBytes]);
                }
            }
        }
        return dwnMessage;
    }
    /**
     * ADDED TO GET SYNC WORKING
     * - createMessage()
     * - processMessage()
     * - writePrunedRecord()
     */
    async createMessage(options) {
        const { author, messageOptions, messageType } = options;
        const dwnSigner = await this.constructDwnSigner(author);
        const messageCreator = dwnMessageCreators[messageType];
        const dwnMessage = await messageCreator.create(Object.assign(Object.assign({}, messageOptions), { signer: dwnSigner }));
        return dwnMessage;
    }
    /**
     * Writes a pruned initial `RecordsWrite` to a DWN without needing to supply associated data.
     * Note: This method should ONLY be used by a {@link SyncManager} implementation.
     *
     * @param options.targetDid - DID of the DWN tenant to write the pruned RecordsWrite to.
     * @returns DWN reply containing the status of processing request.
     */
    async writePrunedRecord(options) {
        const { targetDid, message } = options;
        // @ts-ignore
        return await this._dwn.synchronizePrunedInitialRecordsWrite(targetDid, message);
    }
    async processMessage(options) {
        const { dataStream, message, targetDid } = options;
        // @ts-ignore
        return await this._dwn.processMessage(targetDid, message, dataStream);
    }
}
exports.DwnManager = DwnManager;
//# sourceMappingURL=dwn-manager.js.map