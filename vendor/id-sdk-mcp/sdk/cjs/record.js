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
exports.Record = void 0;
const readable_web_to_node_stream_1 = require("readable-web-to-node-stream");
const id_1 = require("@abaxxtech/id");
const credential_bbs_js_1 = require("./credentials/credential-bbs.js");
const utils_js_1 = require("./utils.js");
/**
 * Record wrapper class with convenience methods to send, update,
 * and delete itself, aside from manipulating and reading the record data.
 *
 * Note: The `messageTimestamp` of the most recent RecordsWrite message is
 *       logically equivalent to the date/time at which a Record was most
 *       recently modified.  Since this Record class implementation is
 *       intended to simplify the developer experience of working with
 *       logical records (and not individual DWN messages) the
 *       `messageTimestamp` is mapped to `dateModified`.
 *
 * @beta
 */
class Record {
    // Immutable DWN Record properties.
    get attestation() { return this._attestation; }
    get contextId() { return this._contextId; }
    get dataFormat() { return this._descriptor.dataFormat; }
    get dateCreated() { return this._descriptor.dateCreated; }
    get encryption() { return this._encryption; }
    get id() { return this._recordId; }
    get interface() { return this._descriptor.interface; }
    get method() { return this._descriptor.method; }
    get parentId() { return this._descriptor.parentId; }
    get protocol() { return this._descriptor.protocol; }
    get protocolPath() { return this._descriptor.protocolPath; }
    get recipient() { return this._descriptor.recipient; }
    get schema() { return this._descriptor.schema; }
    // Mutable DWN Record properties.
    get dataCid() { return this._descriptor.dataCid; }
    get dataSize() { return this._descriptor.dataSize; }
    get dateModified() { return this._descriptor.messageTimestamp; }
    get datePublished() { return this._descriptor.datePublished; }
    get messageTimestamp() { return this._descriptor.messageTimestamp; }
    get published() { return this._descriptor.published; }
    constructor(agent, options) {
        var _a;
        /** Record deleted status */
        this.isDeleted = false;
        this._agent = agent;
        // Store the target and author DIDs that were used to create the message to use for subsequent reads, etc.
        this.author = options.author;
        this.target = options.target;
        // RecordsWriteMessage properties.
        this._attestation = options.attestation;
        this._contextId = options.contextId;
        this._descriptor = options.descriptor;
        this._encryption = options.encryption;
        this._recordId = options.recordId;
        // options.encodedData will either be a base64url encoded string (in the case of RecordsQuery)
        // OR a Blob in the case of a RecordsWrite.
        this._encodedData = (_a = options.encodedData) !== null && _a !== void 0 ? _a : null;
        // If the record was created from a RecordsRead reply then it will have a `data` property.
        if (options.data) {
            this._readableStream = Record.isReadableWebStream(options.data) ?
                new readable_web_to_node_stream_1.ReadableWebToNodeStream(options.data) : options.data;
        }
    }
    /**
     * Returns the data of the current record.
     * If the record data is not available, it attempts to fetch the data from the DWN.
     * @returns a data stream with convenience methods such as `blob()`, `json()`, `text()`, and `stream()`, similar to the fetch API response
     * @throws `Error` if the record has already been deleted.
     *
     */
    get data() {
        if (this.isDeleted)
            throw new Error('Operation failed: Attempted to access `data` of a record that has already been deleted.');
        if (!this._encodedData && !this._readableStream) {
            // `encodedData` will be set if the Record was instantiated by dwn.records.create()/write().
            // `readableStream` will be set if Record was instantiated by dwn.records.read().
            // If neither of the above are true, then the record must be fetched from the DWN.
            this._readableStream = this._agent.processDwnRequest({
                author: this.target,
                messageOptions: { filter: { recordId: this.id } },
                messageType: id_1.DwnInterfaceName.Records + id_1.DwnMethodName.Read,
                target: this.target,
            })
                .then(response => response.reply)
                .then(reply => reply.record.data)
                .catch(error => { throw new Error(`Error encountered while attempting to read data: ${error.message}`); });
        }
        if (typeof this._encodedData === 'string') {
            // If `encodedData` is set, then it is expected that:
            // type is Blob if the Record object was instantiated by dwn.records.create()/write().
            // type is Base64 URL encoded string if the Record object was instantiated by dwn.records.query().
            // If it is a string, we need to Base64 URL decode to bytes and instantiate a Blob.
            const dataBytes = id_1.Encoder.base64UrlToBytes(this._encodedData);
            this._encodedData = new Blob([dataBytes], { type: this.dataFormat });
        }
        // Explicitly cast `encodedData` as a Blob since, if non-null, it has been converted from string to Blob.
        const dataBlob = this._encodedData;
        // eslint-disable-next-line @typescript-eslint/no-this-alias
        const self = this; // Capture the context of the `Record` instance.
        const dataObj = {
            async blob() {
                if (dataBlob)
                    return dataBlob;
                if (self._readableStream)
                    return new Blob([await this.stream().then(id_1.DataStream.toBytes)], { type: self.dataFormat });
            },
            async json() {
                if (dataBlob)
                    return this.text().then(JSON.parse);
                if (self._readableStream)
                    return this.text().then(JSON.parse);
                return null;
            },
            async text() {
                if (dataBlob)
                    return dataBlob.text();
                if (self._readableStream)
                    return this.stream().then(id_1.DataStream.toBytes).then(id_1.Encoder.bytesToString);
                return null;
            },
            async stream() {
                if (dataBlob)
                    return new readable_web_to_node_stream_1.ReadableWebToNodeStream(dataBlob.stream());
                if (self._readableStream)
                    return self._readableStream;
                return null;
            },
            then(...callbacks) {
                return this.stream().then(...callbacks);
            },
            catch(callback) {
                return dataObj.then().catch(callback);
            },
        };
        return dataObj;
    }
    /**
     * Delete the current record from the DWN.
     * @returns the status of the delete request
     * @throws `Error` if the record has already been deleted.
     */
    async delete() {
        if (this.isDeleted)
            throw new Error('Operation failed: Attempted to call `delete()` on a record that has already been deleted.');
        // Attempt to delete the record from the DWN.
        const agentResponse = await this._agent.processDwnRequest({
            author: this.target,
            messageOptions: { recordId: this._recordId },
            messageType: id_1.DwnInterfaceName.Records + id_1.DwnMethodName.Delete,
            target: this.target,
        });
        const { reply: { status } } = agentResponse;
        if (status.code === 202) {
            // If the record was successfully deleted, mark the instance as deleted to prevent further modifications.
            this.setDeletedStatus(true);
        }
        return { status };
    }
    /**
     * Send the current record to a remote DWN by specifying their DID
     * (vs waiting for the regular DWN sync)
     * @param target - the DID to send the record to
     * @returns the status of the send record request
     * @throws `Error` if the record has already been deleted.
     */
    async send(target) {
        if (this.isDeleted)
            throw new Error('Operation failed: Attempted to call `send()` on a record that has already been deleted.');
        let result;
        let status;
        if (typeof target === 'string') {
            result = await this._agent.sendDwnRequest({
                messageType: id_1.DwnInterfaceName.Records + id_1.DwnMethodName.Write,
                author: this.target,
                dataStream: await this.data.blob(),
                target: target,
                messageOptions: this.toJSON(),
            });
            status = result.reply.status;
        }
        else if (Array.isArray(target)) {
            for (let t of target) {
                result = await this._agent.sendDwnRequest({
                    messageType: id_1.DwnInterfaceName.Records + id_1.DwnMethodName.Write,
                    author: this.target,
                    dataStream: await this.data.blob(),
                    target: t,
                    messageOptions: this.toJSON(),
                });
            }
            status = result.reply.status;
        }
        else {
            status = {
                code: 400,
                detail: 'Cannot send the did is invalid',
            };
        }
        return { status };
    }
    /**
     * Sends a BBS+ credential to a remote DWN with selective disclosure.
     * Instead of sending the full credential, this method derives a
     * zero-knowledge proof that reveals only the specified attributes,
     * then writes the derived credential to the target DWN.
     *
     * The record's data must be a BbsSignedCredentialBundle (JSON).
     *
     * @param target - The DID (or array of DIDs) to send the derived credential to.
     * @param options.bundle - The BBS+ signed credential bundle.
     * @param options.revealedAttributes - Attribute names to disclose (e.g. ['country', 'over21']).
     * @param options.issuerPublicKey - The issuer's 96-byte BLS12-381 G2 public key.
     * @param options.nonce - A unique nonce to bind the proof to this verification session.
     * @param options.schema - Optional schema URI for the DWN record.
     * @param options.protocol - Optional protocol URI.
     * @param options.protocolPath - Optional protocol path.
     * @returns The status of the send operation.
     */
    async sendWithSelectiveDisclosure(target, options) {
        if (this.isDeleted) {
            throw new Error('Operation failed: Attempted to call `sendWithSelectiveDisclosure()` on a record that has already been deleted.');
        }
        const { bundle, revealedAttributes, issuerPublicKey, nonce, schema, protocol, protocolPath } = options;
        const derived = await credential_bbs_js_1.BbsCredential.deriveProof(bundle, {
            issuerPublicKey,
            revealedAttributes,
            nonce,
        });
        const derivedJson = JSON.stringify(derived.credential);
        const derivedBlob = new Blob([derivedJson], { type: credential_bbs_js_1.VC_DATA_FORMAT_LDP });
        const messageOptions = Object.assign(Object.assign({}, this.toJSON()), { dataFormat: credential_bbs_js_1.VC_DATA_FORMAT_LDP });
        if (schema)
            messageOptions.schema = schema;
        if (protocol)
            messageOptions.protocol = protocol;
        if (protocolPath)
            messageOptions.protocolPath = protocolPath;
        let result;
        let status;
        const targets = Array.isArray(target) ? target : [target];
        for (const t of targets) {
            result = await this._agent.sendDwnRequest({
                messageType: id_1.DwnInterfaceName.Records + id_1.DwnMethodName.Write,
                author: this.target,
                dataStream: derivedBlob,
                target: t,
                messageOptions,
            });
            status = result.reply.status;
        }
        return { status };
    }
    /**
     * Returns a JSON representation of the Record instance.
     * It's called by `JSON.stringify(...)` automatically.
     */
    toJSON() {
        //@ts-ignore
        return {
            attestation: this.attestation,
            author: this.author,
            contextId: this.contextId,
            dataCid: this.dataCid,
            dataFormat: this.dataFormat,
            dataSize: this.dataSize,
            dateCreated: this.dateCreated,
            messageTimestamp: this.dateModified,
            datePublished: this.datePublished,
            encryption: this.encryption,
            interface: this.interface,
            method: this.method,
            parentId: this.parentId,
            protocol: this.protocol,
            protocolPath: this.protocolPath,
            published: this.published,
            recipient: this.recipient,
            recordId: this.id,
            schema: this.schema,
            target: this.target,
        };
    }
    /**
     * Convenience method to return the string representation of the Record instance.
     * Called automatically in string concatenation, String() type conversion, and template literals.
     */
    toString() {
        let str = `Record: {\n`;
        str += `  id: ${this.id}\n`;
        str += this.contextId ? `  contextId: ${this.contextId}\n` : '';
        str += this.protocol ? `  protocol: ${this.protocol}\n` : '';
        str += this.schema ? `  schema: ${this.schema}\n` : '';
        str += `  dataCid: ${this.dataCid}\n`;
        str += `  dataFormat: ${this.dataFormat}\n`;
        str += `  dataSize: ${this.dataSize}\n`;
        str += `  created: ${this.dateCreated}\n`;
        str += `  modified: ${this.dateModified}\n`;
        str += `}`;
        return str;
    }
    /**
     * Update the current record on the DWN.
     * @param options - options to update the record, including the new data
     * @returns the status of the update request
     * @throws `Error` if the record has already been deleted.
     */
    async update(options = {}) {
        if (this.isDeleted)
            throw new Error('Operation failed: Attempted to call `update()` on a record that has already been deleted.');
        // console.log('this', this);
        const _a = options, { dateModified } = _a, updateOptions = __rest(_a, ["dateModified"]);
        //@ts-ignore
        updateOptions.messageTimestamp = dateModified;
        // Begin assembling update message.
        let updateMessage = Object.assign(Object.assign({}, this._descriptor), updateOptions);
        let dataBlob;
        if (options.data !== undefined) {
            // If `data` is being updated then `dataCid` and `dataSize` must be undefined and the `data` property is passed as
            // a top-level property to `agent.processDwnRequest()`.
            delete updateMessage.dataCid;
            delete updateMessage.dataSize;
            delete updateMessage.data;
            ({ dataBlob } = (0, utils_js_1.dataToBlob)(options.data, updateMessage.dataFormat));
        }
        // Throw an error if an attempt is made to modify immutable properties. `data` has already been handled.
        const mutableDescriptorProperties = new Set(['data', 'dataCid', 'dataSize', 'messageTimestamp', 'datePublished', 'published']);
        Record.verifyPermittedMutation(Object.keys(options), mutableDescriptorProperties);
        // If a new `messageTimestamp` was not provided, remove the equivalent `messageTimestamp` property from from the
        // updateMessage to let the DWN SDK auto-fill. This is necessary because otherwise DWN SDK throws an
        // Error 409 Conflict due to attempting to overwrite a record when the `dateModified` values are identical.
        if (options.dateModified === undefined) {
            delete updateMessage.messageTimestamp;
        }
        // If `published` is set to false, ensure that `datePublished` is undefined. Otherwise, DWN SDK's schema validation
        // will throw an error if `published` is false but `datePublished` is set.
        if (options.published === false && updateMessage.datePublished !== undefined) {
            delete updateMessage.datePublished;
        }
        // Set the record ID and context ID, if any.
        updateMessage.recordId = this._recordId;
        updateMessage.contextId = this._contextId;
        const messageOptions = Object.assign({}, updateMessage);
        const agentResponse = await this._agent.processDwnRequest({
            author: this.target,
            dataStream: dataBlob,
            messageOptions,
            messageType: id_1.DwnInterfaceName.Records + id_1.DwnMethodName.Write,
            target: this.target,
        });
        const { message, reply: { status } } = agentResponse;
        const responseMessage = message;
        if (200 <= status.code && status.code <= 299) {
            // Only update the local Record instance mutable properties if the record was successfully (over)written.
            mutableDescriptorProperties.forEach(property => {
                this._descriptor[property] = responseMessage.descriptor[property];
            });
            // Cache data.
            if (options.data !== undefined) {
                this._encodedData = dataBlob;
            }
        }
        return { status };
    }
    /**
     * Set the deleted status
     */
    setDeletedStatus(status) {
        this.isDeleted = status;
    }
    /**
     * Check is stream is readable.
     */
    static isReadableWebStream(stream) {
        return typeof stream._read !== 'function';
    }
    /**
     * Verify if mutations are permitted.
     */
    static verifyPermittedMutation(propertiesToMutate, mutableDescriptorProperties) {
        for (const property of propertiesToMutate) {
            if (!mutableDescriptorProperties.has(property)) {
                throw new Error(`${property} is an immutable property. Its value cannot be changed.`);
            }
        }
    }
}
exports.Record = Record;
/* snippet
  this simplistic approach would use the first verification method key from the `authentication` property of the DID Document:

  public static async getDefaultSigningKey(options: {
    didDocument: DidDocument
  }): Promise<string | undefined> {
    const { didDocument } = options;

    if (didDocument.authentication
      && Array.isArray(didDocument.authentication)
      && didDocument.authentication.length > 0
      && typeof didDocument.authentication[0] === 'string') {

      const [verificationMethodId] = didDocument.authentication;
      const signingKeyId = verificationMethodId;

      return signingKeyId;
    }
  }
*/
//# sourceMappingURL=record.js.map