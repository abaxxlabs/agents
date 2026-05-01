var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { PrivateKeySigner, } from '@dwn-protocol/id';
import { Convert } from '../common/index.js';
import { Jose } from '../crypto/index.js';
import * as didUtils from '../dids/utils.js';
import { Cid, Dwn, Message, EventsGet, DataStream, RecordsRead, MessagesGet, RecordsWrite, RecordsQuery, DwnMethodName, RecordsDelete, ProtocolsQuery, DwnInterfaceName, ProtocolsConfigure, EventLogLevel, DataStoreLevel, MessageStoreLevel, } from '@dwn-protocol/id';
import { isManagedKeyPair } from './utils.js';
import { blobToIsomorphicNodeReadable, webReadableToIsomorphicNodeReadable } from './utils.js';
const dwnMessageCreators = {
    [DwnInterfaceName.Events + DwnMethodName.Get]: EventsGet,
    [DwnInterfaceName.Messages + DwnMethodName.Get]: MessagesGet,
    [DwnInterfaceName.Records + DwnMethodName.Read]: RecordsRead,
    [DwnInterfaceName.Records + DwnMethodName.Query]: RecordsQuery,
    [DwnInterfaceName.Records + DwnMethodName.Write]: RecordsWrite,
    [DwnInterfaceName.Records + DwnMethodName.Delete]: RecordsDelete,
    [DwnInterfaceName.Protocols + DwnMethodName.Query]: ProtocolsQuery,
    [DwnInterfaceName.Protocols + DwnMethodName.Configure]: ProtocolsConfigure,
};
export class DwnManager {
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
    getSigner(author) {
        return __awaiter(this, void 0, void 0, function* () {
            const signingKeyId = yield this.getAuthorSigningKeyId({ did: author });
            const parsedDid = didUtils.parseDid({ didUrl: signingKeyId });
            if (!parsedDid)
                throw new Error(`DidIonMethod: Unable to parse DID: ${signingKeyId}`);
            const normalizedDid = parsedDid.did.split(':', 3).join(':');
            const normalizedSigningKeyId = `${normalizedDid}#${parsedDid.fragment}`;
            const signingKey = yield this.agent.keyManager.getKey({ keyRef: normalizedSigningKeyId });
            if (!isManagedKeyPair(signingKey)) {
                throw new Error(`DwnManager: Signing key not found for author: '${author}'`);
            }
            const { alg } = Jose.webCryptoToJose(signingKey.privateKey.algorithm);
            if (alg === undefined) {
                throw Error(`No algorithm provided to sign with key ID ${signingKeyId}`);
            }
            return {
                keyId: signingKeyId,
                algorithm: alg,
                sign: (content) => __awaiter(this, void 0, void 0, function* () {
                    return yield this.agent.keyManager.sign({
                        algorithm: signingKey.privateKey.algorithm,
                        data: content,
                        keyRef: normalizedSigningKeyId
                    });
                }),
            };
        });
    }
    /**
     * Constructs a Private Key Signer for a did.
     *
     * @param author - The DID Object.
     * @returns A promise that resolves to the result.
     */
    getPrivateKeySigner(author) {
        return __awaiter(this, void 0, void 0, function* () {
            const signingKeyId = yield this.agent.didManager.getDefaultSigningKey({ did: author.did });
            const signingKeyPair = author.keySet.verificationMethodKeys[0];
            // const signingKeyPair = ionDid.keySet.verificationMethodKeys.find(keyPair => keyPair.publicKeyJwk.kid === "#dwn-sig");
            const signingPrivateKeyJwk = signingKeyPair.privateKeyJwk;
            return [new PrivateKeySigner({
                    privateJwk: signingPrivateKeyJwk,
                    algorithm: signingPrivateKeyJwk.alg,
                    keyId: signingKeyId,
                })];
        });
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
    static create(options) {
        return __awaiter(this, void 0, void 0, function* () {
            let { agent, dataPath, didResolver, dwn } = options !== null && options !== void 0 ? options : {};
            dataPath !== null && dataPath !== void 0 ? dataPath : (dataPath = 'DATA/AGENT');
            if (dwn === undefined) {
                // Use LevelDB stores (browser-compatible)
                const dataStore = new DataStoreLevel({
                    blockstoreLocation: `${dataPath}/DWN_DATASTORE`
                });
                const eventLog = new EventLogLevel({
                    location: `${dataPath}/DWN_EVENTLOG`
                });
                const messageStore = new MessageStoreLevel(({
                    blockstoreLocation: `${dataPath}/DWN_MESSAGESTORE`,
                    indexLocation: `${dataPath}/DWN_MESSAGEINDEX`
                }));
                // Note: PostgreSQL stores commented out - use environment variable or config to enable
                // const messageStore = new MessageStoreSql(postgresDialect);
                // const dataStore = new DataStoreSql(postgresDialect);
                // const eventLog = new EventLogSql(postgresDialect);
                dwn = yield Dwn.create({
                    dataStore,
                    //@ts-ignore
                    didResolver,
                    eventLog,
                    messageStore,
                });
            }
            return new DwnManager({ agent, dwn });
        });
    }
    processRequest(request) {
        return __awaiter(this, void 0, void 0, function* () {
            const { message, dataStream } = yield this.constructDwnMessage({ request });
            let reply;
            if (request.store !== false) {
                // @ts-ignore
                reply = yield this._dwn.processMessage(request.target, message, dataStream);
            }
            else {
                reply = { status: { code: 202, detail: 'Accepted' } };
            }
            return {
                reply,
                message: message,
                messageCid: yield Message.getCid(message)
            };
        });
    }
    sendRequest(request) {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
            const dwnRpcRequest = { targetDid: request.target };
            let messageData;
            if ('messageCid' in request) {
                const { message, data } = yield this.getDwnMessage({
                    author: request.author,
                    messageCid: request.messageCid,
                    messageType: request.messageType
                });
                dwnRpcRequest.message = message;
                messageData = data;
            }
            else {
                const { message } = yield this.constructDwnMessage({ request });
                dwnRpcRequest.message = message;
                messageData = request.dataStream;
            }
            if (messageData) {
                dwnRpcRequest.data = messageData;
            }
            const { didDocument, didResolutionMetadata } = yield this.agent.didResolver.resolve(request.target);
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
                    dwnReply = yield this.agent.rpcClient.sendDwnRequest(dwnRpcRequest);
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
                        ? yield this.messageDataToBase64(messageData)
                        : undefined;
                    yield this.agent.outbox.enqueue(Object.assign({ targetDid: request.target, dwnUrls: dwnEndpointUrls, message: dwnRpcRequest.message }, (dataBase64 !== undefined && { dataBase64 })));
                    return {
                        message: dwnRpcRequest.message,
                        messageCid: yield Message.getCid(dwnRpcRequest.message),
                        reply: { status: { code: 202, detail: 'Queued for delivery when online' } },
                    };
                }
                throw new Error(JSON.stringify(errorMessages));
            }
            return {
                message: dwnRpcRequest.message,
                messageCid: yield Message.getCid(dwnRpcRequest.message),
                reply: dwnReply,
            };
        });
    }
    messageDataToBase64(data) {
        return __awaiter(this, void 0, void 0, function* () {
            if (data instanceof Blob) {
                const u8a = new Uint8Array(yield data.arrayBuffer());
                return Convert.uint8Array(u8a).toBase64Url();
            }
            const u8a = yield Convert.asyncIterable(data).toUint8ArrayAsync();
            return Convert.uint8Array(u8a).toBase64Url();
        });
    }
    constructDwnMessage(options) {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
            const { request } = options;
            let readableStream;
            if (request.messageType === 'RecordsWrite') {
                const messageOptions = request.messageOptions;
                if (request.dataStream && !messageOptions.data) {
                    const { dataStream } = request;
                    let isomorphicNodeReadable;
                    if (dataStream instanceof Blob) {
                        isomorphicNodeReadable = blobToIsomorphicNodeReadable(dataStream);
                        readableStream = blobToIsomorphicNodeReadable(dataStream);
                    }
                    else if (dataStream instanceof ReadableStream) {
                        const [forCid, forProcessMessage] = dataStream.tee();
                        isomorphicNodeReadable = webReadableToIsomorphicNodeReadable(forCid);
                        readableStream = webReadableToIsomorphicNodeReadable(forProcessMessage);
                    }
                    // @ts-ignore
                    messageOptions.dataCid = yield Cid.computeDagPbCidFromStream(isomorphicNodeReadable);
                    // @ts-ignore
                    (_a = messageOptions.dataSize) !== null && _a !== void 0 ? _a : (messageOptions.dataSize = isomorphicNodeReadable['bytesRead']);
                }
            }
            const dwnSigner = yield this.constructDwnSigner(request.author);
            const messageCreator = dwnMessageCreators[request.messageType];
            const dwnMessage = yield messageCreator.create(Object.assign(Object.assign({}, request.messageOptions), { signer: dwnSigner }));
            // return { message: dwnMessage.toJSON(), dataStream: readableStream };
            return { message: dwnMessage.message, dataStream: readableStream };
        });
    }
    getAuthorSigningKeyId(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const { did } = options;
            // Get the method-specific default signing key.
            const signingKeyId = yield this.agent.didManager.getDefaultSigningKey({ did });
            if (!signingKeyId) {
                throw new Error(`DwnManager: Unable to determine signing key for author: '${did}'`);
            }
            return signingKeyId;
        });
    }
    constructDwnSigner(author) {
        return __awaiter(this, void 0, void 0, function* () {
            const signingKeyId = yield this.getAuthorSigningKeyId({ did: author });
            /**
             * DID keys stored in KeyManager use the canonicalId as an alias, so
             * normalize the signing key ID before attempting to retrieve the key.
             */
            const parsedDid = didUtils.parseDid({ didUrl: signingKeyId });
            if (!parsedDid)
                throw new Error(`DidIonMethod: Unable to parse DID: ${signingKeyId}`);
            const normalizedDid = parsedDid.did.split(':', 3).join(':');
            const normalizedSigningKeyId = `${normalizedDid}#${parsedDid.fragment}`;
            const signingKey = yield this.agent.keyManager.getKey({ keyRef: normalizedSigningKeyId });
            if (!isManagedKeyPair(signingKey)) {
                throw new Error(`DwnManager: Signing key not found for author: '${author}'`);
            }
            const { alg } = Jose.webCryptoToJose(signingKey.privateKey.algorithm);
            if (alg === undefined) {
                throw Error(`No algorithm provided to sign with key ID ${signingKeyId}`);
            }
            return {
                keyId: signingKeyId,
                algorithm: alg,
                sign: (content) => __awaiter(this, void 0, void 0, function* () {
                    return yield this.agent.keyManager.sign({
                        algorithm: signingKey.privateKey.algorithm,
                        data: content,
                        keyRef: normalizedSigningKeyId
                    });
                })
            };
        });
    }
    getDwnMessage(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const { author, messageType, messageCid } = options;
            const dwnSigner = yield this.constructDwnSigner(author);
            const messagesGet = yield MessagesGet.create({
                messageCids: [messageCid],
                signer: dwnSigner
            });
            const result = yield this._dwn.processMessage(author, messagesGet.message);
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
                    const dataBytes = Convert.base64Url(encodedData).toUint8Array();
                    dwnMessage.data = new Blob([dataBytes]);
                }
                else {
                    const recordsRead = yield RecordsRead.create({
                        filter: {
                            recordId: writeMessage.recordId
                        },
                        signer: dwnSigner
                    });
                    const reply = yield this._dwn.processMessage(author, recordsRead.message);
                    if (reply.status.code >= 400) {
                        const { status: { code, detail } } = reply;
                        throw new Error(`(${code}) Failed to read data associated with record ${writeMessage.recordId}. ${detail}}`);
                    }
                    else if (reply.record) {
                        const dataBytes = yield DataStream.toBytes(reply.record.data);
                        dwnMessage.data = new Blob([dataBytes]);
                    }
                }
            }
            return dwnMessage;
        });
    }
    /**
     * ADDED TO GET SYNC WORKING
     * - createMessage()
     * - processMessage()
     * - writePrunedRecord()
     */
    createMessage(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const { author, messageOptions, messageType } = options;
            const dwnSigner = yield this.constructDwnSigner(author);
            const messageCreator = dwnMessageCreators[messageType];
            const dwnMessage = yield messageCreator.create(Object.assign(Object.assign({}, messageOptions), { signer: dwnSigner }));
            return dwnMessage;
        });
    }
    /**
     * Writes a pruned initial `RecordsWrite` to a DWN without needing to supply associated data.
     * Note: This method should ONLY be used by a {@link SyncManager} implementation.
     *
     * @param options.targetDid - DID of the DWN tenant to write the pruned RecordsWrite to.
     * @returns DWN reply containing the status of processing request.
     */
    writePrunedRecord(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const { targetDid, message } = options;
            // @ts-ignore
            return yield this._dwn.synchronizePrunedInitialRecordsWrite(targetDid, message);
        });
    }
    processMessage(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const { dataStream, message, targetDid } = options;
            // @ts-ignore
            return yield this._dwn.processMessage(targetDid, message, dataStream);
        });
    }
}
//# sourceMappingURL=dwn-manager.js.map