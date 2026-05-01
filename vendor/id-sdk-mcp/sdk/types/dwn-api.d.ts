import type { IDAgent } from './agent/index.js';
import type { RecordsReadOptions, RecordsQueryOptions, RecordsWriteOptions, RecordsDeleteOptions, ProtocolsQueryOptions, ProtocolsConfigureOptions, ProtocolsConfigureDescriptor } from '@dwn-protocol/id';
import { Record } from './record.js';
import { Protocol } from './protocol.js';
/**
 * Status code and detailed message for a response.
 *
 * @beta
 */
export type ResponseStatus = {
    status: {
        code: number;
        detail: string;
    };
};
/**
 * Request to setup a protocol with its definitions
 *
 * @beta
 */
export type ProtocolsConfigureRequest = {
    message: Omit<ProtocolsConfigureOptions, 'signer'>;
};
/**
 * Response for the protocol configure request
 *
 * @beta
 */
export type ProtocolsConfigureResponse = ResponseStatus & {
    protocol?: Protocol;
};
/**
 * Represents each entry on the protocols query reply
 *
 * @beta
 */
export type ProtocolsQueryReplyEntry = {
    descriptor: ProtocolsConfigureDescriptor;
};
/**
 * Request to query protocols
 *
 * @beta
 */
export type ProtocolsQueryRequest = {
    from?: string;
    message: Omit<ProtocolsQueryOptions, 'signer'>;
};
/**
 * Response with the retrieved protocols
 *
 * @beta
 */
export type ProtocolsQueryResponse = ResponseStatus & {
    protocols: Protocol[];
};
/**
 * Type alias for {@link RecordsWriteRequest}
 *
 * @beta
 */
export type RecordsCreateRequest = RecordsWriteRequest;
/**
 * Type alias for {@link RecordsWriteResponse}
 *
 * @beta
 */
export type RecordsCreateResponse = RecordsWriteResponse;
/**
 * Request to create a record from an existing one (useful for updating an existing record)
 *
 * @beta
 */
export type RecordsCreateFromRequest = {
    author: string;
    data: unknown;
    message?: Omit<RecordsWriteOptions, 'signer'>;
    record: Record;
    target?: string;
};
/**
 * Request to delete a record from the DWN
 *
 * @beta
 */
export type RecordsDeleteRequest = {
    from?: string;
    message: Omit<RecordsDeleteOptions, 'signer'>;
};
/**
 * Response for the read request
 *
 * @beta
 */
export type RecordsQueryRequest = {
    /** The from property indicates the DID to query from and return results. */
    from?: string;
    message: Omit<RecordsQueryOptions, 'signer'>;
};
/**
 * Response for the query request
 *
 * @beta
 */
export type RecordsQueryResponse = ResponseStatus & {
    records?: Record[];
    /** If there are additional results, the messageCid of the last record will be returned as a pagination cursor. */
    cursor?: string;
};
/**
 * Request to read a record from the DWN
 *
 * @beta
 */
export type RecordsReadRequest = {
    /** The from property indicates the DID to read from and return results fro. */
    from?: string;
    message: Omit<RecordsReadOptions, 'signer'>;
};
/**
 * Response for the read request
 *
 * @beta
 */
export type RecordsReadResponse = ResponseStatus & {
    record: Record;
};
/**
 * Request to write a record to the DWN
 *
 * @beta
 */
export type RecordsWriteRequest = {
    data: unknown;
    message?: Omit<Partial<RecordsWriteOptions>, 'signer'>;
    store?: boolean;
    target?: string;
};
/**
 * Response for the write request
 *
 * @beta
 */
export type RecordsWriteResponse = ResponseStatus & {
    record?: Record;
};
/**
 * Interface to interact with DWN Records and Protocols
 *
 * @beta
 */
export declare class DwnApi {
    private agent;
    private connectedDid;
    constructor(options: {
        agent: IDAgent;
        connectedDid: string;
    });
    /**
    * API to interact with DWN protocols (e.g., `dwn.protocols.configure()`).
    */
    get protocols(): {
        /**
         * Configure method, used to setup a new protocol (or update) with the passed definitions
         */
        configure: (request: ProtocolsConfigureRequest) => Promise<ProtocolsConfigureResponse>;
        /**
         * Query the available protocols
         */
        query: (request: ProtocolsQueryRequest) => Promise<ProtocolsQueryResponse>;
    };
    /**
     * API to interact with DWN records (e.g., `dwn.records.create()`).
     */
    get records(): {
        /**
         * Alias for the `write` method
         */
        create: (request: RecordsCreateRequest) => Promise<RecordsCreateResponse>;
        /**
         * Write a record based on an existing one (useful for updating an existing record)
         */
        createFrom: (request: RecordsCreateFromRequest) => Promise<RecordsWriteResponse>;
        /**
         * Delete a record
         */
        delete: (request: RecordsDeleteRequest) => Promise<ResponseStatus>;
        /**
         * Query a single or multiple records based on the given filter
         */
        query: (request: RecordsQueryRequest) => Promise<RecordsQueryResponse>;
        /**
         * Read a single record based on the given filter
         */
        read: (request: RecordsReadRequest) => Promise<RecordsReadResponse>;
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
        write: (request: RecordsWriteRequest) => Promise<RecordsWriteResponse>;
    };
    /**
     * API to retrieve the service nodes via did:web:dwn.x.id.
     */
    getServiceNodes(): Promise<any>;
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
    resolveRecipientEncryptionKeys(recipientDid: string, options?: {
        useRelayEndpoint?: boolean;
        relayUrl?: string;
    }): Promise<Array<{
        keyId: string;
        publicKeyJwk: any;
        keyType: string;
    }>>;
}
//# sourceMappingURL=dwn-api.d.ts.map