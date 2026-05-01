import type { IDAgent } from './agent/index.js';
import type { Readable } from 'readable-stream';
import type { RecordsWriteMessage, RecordsWriteDescriptor } from '@dwn-protocol/id';
import type { BbsSignedCredentialBundle } from './credentials/credential-bbs.js';
import { DwnInterfaceName, DwnMethodName } from '@dwn-protocol/id';
import type { ResponseStatus } from './dwn-api.js';
/**
 * Options that are passed to Record constructor.
 *
 * @beta
 */
export type RecordOptions = RecordsWriteMessage & {
    author: string;
    target: string;
    encodedData?: string | Blob;
    data?: Readable | ReadableStream;
};
/**
 * Represents the record data model, without the auxiliary properties such as
 * the `descriptor` and the `authorization`
 *
 * @beta
 */
export type RecordModel = RecordsWriteDescriptor & Omit<RecordsWriteMessage, 'descriptor' | 'recordId' | 'authorization'> & {
    author: string;
    recordId?: string;
    target: string;
};
/**
 * Options that are passed to update the record on the DWN
 *
 * @beta
 */
export type RecordUpdateOptions = {
    data?: unknown;
    dataCid?: RecordsWriteDescriptor['dataCid'];
    dataSize?: RecordsWriteDescriptor['dataSize'];
    dateModified?: RecordsWriteDescriptor['messageTimestamp'];
    datePublished?: RecordsWriteDescriptor['datePublished'];
    published?: RecordsWriteDescriptor['published'];
};
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
export declare class Record implements RecordModel {
    /** Record's author */
    author: string;
    /** Record's target (for sent records) */
    target: string;
    /** Record deleted status */
    isDeleted: boolean;
    private _agent;
    private _attestation?;
    private _contextId?;
    private _descriptor;
    private _encodedData?;
    private _encryption?;
    private _readableStream?;
    private _recordId;
    get attestation(): RecordsWriteMessage['attestation'];
    get contextId(): string;
    get dataFormat(): string;
    get dateCreated(): string;
    get encryption(): RecordsWriteMessage['encryption'];
    get id(): string;
    get interface(): DwnInterfaceName.Records;
    get method(): DwnMethodName.Write;
    get parentId(): string;
    get protocol(): string;
    get protocolPath(): string;
    get recipient(): string;
    get schema(): string;
    get dataCid(): string;
    get dataSize(): number;
    get dateModified(): string;
    get datePublished(): string;
    get messageTimestamp(): string;
    get published(): boolean;
    constructor(agent: IDAgent, options: RecordOptions);
    /**
     * Returns the data of the current record.
     * If the record data is not available, it attempts to fetch the data from the DWN.
     * @returns a data stream with convenience methods such as `blob()`, `json()`, `text()`, and `stream()`, similar to the fetch API response
     * @throws `Error` if the record has already been deleted.
     *
     */
    get data(): {
        blob(): Promise<Blob>;
        json(): Promise<any>;
        text(): Promise<any>;
        stream(): Promise<Readable>;
        then(...callbacks: any[]): any;
        catch(callback: any): any;
    };
    /**
     * Delete the current record from the DWN.
     * @returns the status of the delete request
     * @throws `Error` if the record has already been deleted.
     */
    delete(): Promise<ResponseStatus>;
    /**
     * Send the current record to a remote DWN by specifying their DID
     * (vs waiting for the regular DWN sync)
     * @param target - the DID to send the record to
     * @returns the status of the send record request
     * @throws `Error` if the record has already been deleted.
     */
    send(target: any): Promise<ResponseStatus>;
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
    sendWithSelectiveDisclosure(target: string | string[], options: {
        bundle: BbsSignedCredentialBundle;
        revealedAttributes: string[];
        issuerPublicKey: Uint8Array;
        nonce: string;
        schema?: string;
        protocol?: string;
        protocolPath?: string;
    }): Promise<ResponseStatus>;
    /**
     * Returns a JSON representation of the Record instance.
     * It's called by `JSON.stringify(...)` automatically.
     */
    toJSON(): RecordModel;
    /**
     * Convenience method to return the string representation of the Record instance.
     * Called automatically in string concatenation, String() type conversion, and template literals.
     */
    toString(): string;
    /**
     * Update the current record on the DWN.
     * @param options - options to update the record, including the new data
     * @returns the status of the update request
     * @throws `Error` if the record has already been deleted.
     */
    update(options?: RecordUpdateOptions): Promise<ResponseStatus>;
    /**
     * Set the deleted status
     */
    private setDeletedStatus;
    /**
     * Check is stream is readable.
     */
    private static isReadableWebStream;
    /**
     * Verify if mutations are permitted.
     */
    private static verifyPermittedMutation;
}
//# sourceMappingURL=record.d.ts.map