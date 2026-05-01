var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { Level } from 'level';
import { Convert } from '../common/index.js';
import { utils as didUtils } from '../dids/index.js';
import { DataStream } from '@dwn-protocol/id';
import { webReadableToIsomorphicNodeReadable } from './utils.js';
const is2xx = (code) => code >= 200 && code <= 299;
const is4xx = (code) => code >= 400 && code <= 499;
export class SyncManagerLevel {
    constructor(options) {
        let { agent, dataPath = 'data/AGENT/SYNC_STORE', db } = options !== null && options !== void 0 ? options : {};
        this._agent = agent;
        this._db = (db) ? db : new Level(dataPath);
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
    clear() {
        return __awaiter(this, void 0, void 0, function* () {
            yield this._db.clear();
        });
    }
    pull() {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
            const syncPeerState = yield this.getSyncPeerState({ syncDirection: 'pull' });
            yield this.enqueueOperations({ syncDirection: 'pull', syncPeerState });
            const pullQueue = this.getPullQueue();
            const pullJobs = yield pullQueue.iterator().all();
            const deleteOperations = [];
            const errored = new Set();
            for (let job of pullJobs) {
                const [key] = job;
                const [did, dwnUrl, watermark, messageCid] = key.split('~');
                // If a particular DWN service endpoint is unreachable, skip subsequent pull operations.
                if (errored.has(dwnUrl)) {
                    continue;
                }
                const messageExists = yield this.messageExists(did, messageCid);
                if (messageExists) {
                    yield this.setWatermark(did, dwnUrl, 'pull', watermark);
                    deleteOperations.push({ type: 'del', key: key });
                    continue;
                }
                const messagesGet = yield this.agent.dwnManager.createMessage({
                    author: did,
                    messageType: 'MessagesGet',
                    messageOptions: {
                        messageCids: [messageCid]
                    }
                });
                let reply;
                try {
                    reply = (yield this.agent.rpcClient.sendDwnRequest({
                        dwnUrl,
                        targetDid: did,
                        message: messagesGet
                    }));
                }
                catch (e) {
                    errored.add(dwnUrl);
                    continue;
                }
                for (let entry of (_a = reply.messages) !== null && _a !== void 0 ? _a : []) {
                    if (entry.error || !entry.message) {
                        yield this.setWatermark(did, dwnUrl, 'pull', watermark);
                        yield this.addMessage(did, messageCid);
                        deleteOperations.push({ type: 'del', key: key });
                        continue;
                    }
                    const messageType = this.getDwnMessageType(entry.message);
                    let dataStream;
                    if (messageType === 'RecordsWrite') {
                        const { encodedData } = entry;
                        const message = entry.message;
                        if (encodedData) {
                            const dataBytes = Convert.base64Url(encodedData).toUint8Array();
                            dataStream = DataStream.fromBytes(dataBytes);
                        }
                        else {
                            const recordsRead = yield this.agent.dwnManager.createMessage({
                                author: did,
                                messageType: 'RecordsRead',
                                messageOptions: {
                                    filter: {
                                        recordId: message.recordId
                                    }
                                }
                            });
                            const recordsReadReply = yield this.agent.rpcClient.sendDwnRequest({
                                dwnUrl,
                                targetDid: did,
                                message: recordsRead.message
                            });
                            const { record, status: readStatus } = recordsReadReply;
                            if (is2xx(readStatus.code) && record) {
                                /** If the read was successful, convert the data stream from web ReadableStream
                                   * to Node.js Readable so that the DWN can process it.*/
                                dataStream = webReadableToIsomorphicNodeReadable(record.data);
                            }
                            else if (readStatus.code >= 400) {
                                const pruneReply = yield this.agent.dwnManager.writePrunedRecord({
                                    targetDid: did,
                                    message
                                });
                                if (pruneReply.status.code === 202 || pruneReply.status.code === 409) {
                                    yield this.setWatermark(did, dwnUrl, 'pull', watermark);
                                    yield this.addMessage(did, messageCid);
                                    deleteOperations.push({ type: 'del', key: key });
                                    continue;
                                }
                                else {
                                    throw new Error(`SyncManager: Failed to sync tombstone for message '${messageCid}'`);
                                }
                            }
                        }
                    }
                    const pullReply = yield this.agent.dwnManager.processMessage({
                        targetDid: did,
                        message: entry.message,
                        dataStream
                    });
                    if (pullReply.status.code === 202 || pullReply.status.code === 409) {
                        yield this.setWatermark(did, dwnUrl, 'pull', watermark);
                        yield this.addMessage(did, messageCid);
                        deleteOperations.push({ type: 'del', key: key });
                    }
                }
            }
            yield pullQueue.batch(deleteOperations);
        });
    }
    push() {
        return __awaiter(this, void 0, void 0, function* () {
            const syncPeerState = yield this.getSyncPeerState({ syncDirection: 'push' });
            yield this.enqueueOperations({ syncDirection: 'push', syncPeerState });
            const pushQueue = this.getPushQueue();
            const pushJobs = yield pushQueue.iterator().all();
            const deleteOperations = [];
            const errored = new Set();
            for (let job of pushJobs) {
                const [key] = job;
                const [did, dwnUrl, watermark, messageCid] = key.split('~');
                // If a particular DWN service endpoint is unreachable, skip subsequent push operations.
                if (errored.has(dwnUrl)) {
                    continue;
                }
                // If this message was already synced (e.g., pulled from remote), skip to prevent ping-pong.
                const messageExists = yield this.messageExists(did, messageCid);
                if (messageExists) {
                    deleteOperations.push({ type: 'del', key: key });
                    yield this.setWatermark(did, dwnUrl, 'push', watermark);
                    continue;
                }
                // Attempt to retrieve the message from the local DWN.
                let dwnMessage;
                try {
                    dwnMessage = yield this.getDwnMessage(did, messageCid);
                }
                catch (_a) {
                    // If the message can't be retrieved, skip it and advance.
                    deleteOperations.push({ type: 'del', key: key });
                    yield this.setWatermark(did, dwnUrl, 'push', watermark);
                    yield this.addMessage(did, messageCid);
                    continue;
                }
                /** If the message does not exist on the local DWN, remove the sync operation from the
                 * push queue, update the push watermark for this DID/DWN endpoint combination, add the
                 * message to the local message store, and continue to the next job. */
                if (!dwnMessage) {
                    deleteOperations.push({ type: 'del', key: key });
                    yield this.setWatermark(did, dwnUrl, 'push', watermark);
                    yield this.addMessage(did, messageCid);
                    continue;
                }
                try {
                    const reply = yield this.agent.rpcClient.sendDwnRequest({
                        dwnUrl,
                        targetDid: did,
                        data: dwnMessage.data,
                        message: dwnMessage.message
                    });
                    /** Update the watermark and add the messageCid to the Sync Message Store if either:
                     * - 202: message was successfully written to the remote DWN
                     * - 409: message was already present on the remote DWN
                     */
                    if (reply.status.code === 202 || reply.status.code === 409) {
                        yield this.setWatermark(did, dwnUrl, 'push', watermark);
                        yield this.addMessage(did, messageCid);
                        deleteOperations.push({ type: 'del', key: key });
                    }
                }
                catch (_b) {
                    // Error is intentionally ignored; 'errored' set is updated with 'dwnUrl'.
                    errored.add(dwnUrl);
                }
            }
            yield pushQueue.batch(deleteOperations);
        });
    }
    registerIdentity(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const { did } = options;
            const registeredIdentities = this._db.sublevel('registeredIdentities');
            yield registeredIdentities.put(did, '');
        });
    }
    startSync(options) {
        const { interval = 60000 } = options;
        if (this._syncIntervalId) {
            clearInterval(this._syncIntervalId);
        }
        this._syncIntervalId = setInterval(() => __awaiter(this, void 0, void 0, function* () {
            try {
                yield this.push();
            }
            catch (error) {
                console.error('SyncManager: push error:', error);
            }
            try {
                yield this.pull();
            }
            catch (error) {
                console.error('SyncManager: pull error:', error);
            }
        }), interval);
        return Promise.resolve();
    }
    /**
     * Run one cycle of push, pull, and outbox drain. Used by the sync interval
     * and by flushOutboxAndSync() for on-demand sync.
     */
    runNow() {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
            yield this.push();
            yield this.pull();
            yield ((_a = this.agent.outbox) === null || _a === void 0 ? void 0 : _a.drain());
        });
    }
    stopSync() {
        if (this._syncIntervalId) {
            clearInterval(this._syncIntervalId);
            this._syncIntervalId = undefined;
        }
    }
    enqueueOperations(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const { syncDirection, syncPeerState } = options;
            for (let syncState of syncPeerState) {
                // Get the event log from the remote DWN if pull sync, or local DWN if push sync.
                const eventLog = yield this.getDwnEventLog({
                    did: syncState.did,
                    dwnUrl: syncState.dwnUrl,
                    syncDirection,
                    watermark: syncState.watermark
                });
                const syncOperations = [];
                for (let event of eventLog) {
                    /** Use "did~dwnUrl~watermark~messageCid" as the key in the sync queue.
                     * Note: It is critical that `watermark` precedes `messageCid` to
                     * ensure that when the sync jobs are pulled off the queue, they
                     * are lexographically sorted oldest to newest. */
                    const operationKey = [
                        syncState.did,
                        syncState.dwnUrl,
                        event.watermark,
                        event.messageCid
                    ].join('~');
                    const operation = { type: 'put', key: operationKey, value: '' };
                    syncOperations.push(operation);
                }
                if (syncOperations.length > 0) {
                    const syncQueue = (syncDirection === 'pull')
                        ? this.getPullQueue()
                        : this.getPushQueue();
                    yield syncQueue.batch(syncOperations);
                }
            }
        });
    }
    getDwnEventLog(options) {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
            const { did, dwnUrl, syncDirection, watermark } = options;
            let eventsReply = {};
            if (syncDirection === 'pull') {
                // When sync is a pull, get the event log from the remote DWN.
                const eventsGetMessage = yield this.agent.dwnManager.createMessage({
                    author: did,
                    messageType: 'EventsGet',
                    messageOptions: { watermark }
                });
                try {
                    eventsReply = yield this.agent.rpcClient.sendDwnRequest({
                        dwnUrl: dwnUrl,
                        targetDid: did,
                        message: eventsGetMessage
                    });
                }
                catch (_b) {
                    // If a particular DWN service endpoint is unreachable, silently ignore.
                }
            }
            else if (syncDirection === 'push') {
                // When sync is a push, get the event log from the local DWN.
                ({ reply: eventsReply } = yield this.agent.dwnManager.processRequest({
                    author: did,
                    target: did,
                    messageType: 'EventsGet',
                    messageOptions: { watermark }
                }));
            }
            const eventLog = (_a = eventsReply.events) !== null && _a !== void 0 ? _a : [];
            return eventLog;
        });
    }
    getDwnMessage(author, messageCid) {
        return __awaiter(this, void 0, void 0, function* () {
            let messagesGetResponse = yield this.agent.dwnManager.processRequest({
                author: author,
                target: author,
                messageType: 'MessagesGet',
                messageOptions: {
                    messageCids: [messageCid]
                }
            });
            const reply = messagesGetResponse.reply;
            /** Absence of a messageEntry or message within messageEntry can happen because updating a
             * Record creates another RecordsWrite with the same recordId. Only the first and
             * most recent RecordsWrite messages are kept for a given recordId. Any RecordsWrite messages
             * that aren't the first or most recent are discarded by the DWN. */
            if (!(reply.messages && reply.messages.length === 1)) {
                return undefined;
            }
            const [messageEntry] = reply.messages;
            let { message } = messageEntry;
            if (!message) {
                return undefined;
            }
            let dwnMessage = { message };
            const messageType = `${message.descriptor.interface}${message.descriptor.method}`;
            // if the message is a RecordsWrite, either data will be present, OR we have to get it using a RecordsRead
            if (messageType === 'RecordsWrite') {
                const { encodedData } = messageEntry;
                const writeMessage = message;
                if (encodedData) {
                    const dataBytes = Convert.base64Url(encodedData).toUint8Array();
                    dwnMessage.data = new Blob([dataBytes]);
                }
                else {
                    let readResponse = yield this.agent.dwnManager.processRequest({
                        author: author,
                        target: author,
                        messageType: 'RecordsRead',
                        messageOptions: {
                            filter: {
                                recordId: writeMessage.recordId
                            }
                        }
                    });
                    const reply = readResponse.reply;
                    if (is2xx(reply.status.code) && reply.record) {
                        // If status code is 200-299, return the data.
                        const dataBytes = yield DataStream.toBytes(reply.record.data);
                        dwnMessage.data = new Blob([dataBytes]);
                    }
                    else if (is4xx(reply.status.code)) {
                        /** If status code is 400-499, typically 404 indicating the data no longer exists, it is
                         * likely that a `RecordsDelete` took place. `RecordsDelete` keeps a `RecordsWrite` and
                         * deletes the associated data, effectively acting as a "tombstone."  Sync still needs to
                         * _push_ this tombstone so that the `RecordsDelete` can be processed successfully. */
                    }
                    else {
                        // If status code is anything else (likely 5xx), throw an error.
                        const { status } = reply;
                        throw new Error(`SyncManager: Failed to read data associated with record ${writeMessage.recordId}. (${status.code}) ${status.detail}}`);
                    }
                }
            }
            return dwnMessage;
        });
    }
    getSyncPeerState(options) {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
            const { syncDirection } = options;
            // Get a list of the DIDs of all registered identities.
            const registeredIdentities = yield this._db.sublevel('registeredIdentities').keys().all();
            // Array to accumulate the list of sync peers for each DID.
            const syncPeerState = [];
            for (let did of registeredIdentities) {
                // Resolve the DID to its DID document.
                const { didDocument, didResolutionMetadata } = yield this.agent.didResolver.resolve(did);
                // If DID resolution fails, throw an error.
                if (!didDocument) {
                    const errorCode = `${didResolutionMetadata === null || didResolutionMetadata === void 0 ? void 0 : didResolutionMetadata.error}: ` || '';
                    const defaultMessage = `Unable to resolve DID: ${did}`;
                    const errorMessage = (_a = didResolutionMetadata === null || didResolutionMetadata === void 0 ? void 0 : didResolutionMetadata.errorMessage) !== null && _a !== void 0 ? _a : defaultMessage;
                    throw new Error(`SyncManager: ${errorCode}${errorMessage}`);
                }
                // Attempt to get the `#dwn` service entry from the DID document.
                const [service] = didUtils.getServices({ didDocument, id: '#dwn' });
                /** Silently ignore and do not try to perform Sync for any DID that does not have a DWN
                 * service endpoint published in its DID document. **/
                if (!service) {
                    continue;
                }
                if (!didUtils.isDwnServiceEndpoint(service.serviceEndpoint)) {
                    throw new Error(`SyncManager: Malformed '#dwn' service endpoint. Expected array of node addresses.`);
                }
                /** Get the watermark (or undefined) for each (DID, DWN service endpoint, sync direction)
                 * combination and add it to the sync peer state array. */
                for (let dwnUrl of service.serviceEndpoint.nodes) {
                    const watermark = yield this.getWatermark(did, dwnUrl, syncDirection);
                    syncPeerState.push({ did, dwnUrl, watermark });
                }
            }
            return syncPeerState;
        });
    }
    getWatermark(did, dwnUrl, direction) {
        return __awaiter(this, void 0, void 0, function* () {
            const wmKey = `${did}~${dwnUrl}~${direction}`;
            const watermarkStore = this.getWatermarkStore();
            try {
                return yield watermarkStore.get(wmKey);
            }
            catch (error) {
                // Don't throw when a key wasn't found.
                if (error.notFound) {
                    return undefined;
                }
            }
        });
    }
    setWatermark(did, dwnUrl, direction, watermark) {
        return __awaiter(this, void 0, void 0, function* () {
            const wmKey = `${did}~${dwnUrl}~${direction}`;
            const watermarkStore = this.getWatermarkStore();
            yield watermarkStore.put(wmKey, watermark);
        });
    }
    /**
     * The message store is used to prevent "echoes" that occur during a sync pull operation.
     * After a message is confirmed to already be synchronized on the local DWN, its CID is added
     * to the message store to ensure that any subsequent pull attempts are skipped.
     */
    messageExists(did, messageCid) {
        return __awaiter(this, void 0, void 0, function* () {
            const messageStore = this.getMessageStore(did);
            // If the `messageCid` exists in this DID's store, return true. Otherwise, return false.
            try {
                yield messageStore.get(messageCid);
                return true;
            }
            catch (error) {
                if (error.notFound) {
                    return false;
                }
                throw error;
            }
        });
    }
    addMessage(did, messageCid) {
        return __awaiter(this, void 0, void 0, function* () {
            const messageStore = this.getMessageStore(did);
            return yield messageStore.put(messageCid, '');
        });
    }
    getMessageStore(did) {
        return this._db.sublevel('history').sublevel(did).sublevel('messages');
    }
    getWatermarkStore() {
        return this._db.sublevel('watermarks');
    }
    getPushQueue() {
        return this._db.sublevel('pushQueue');
    }
    getPullQueue() {
        return this._db.sublevel('pullQueue');
    }
    getDwnMessageType(message) {
        return `${message.descriptor.interface}${message.descriptor.method}`;
    }
}
//# sourceMappingURL=sync-manager.js.map