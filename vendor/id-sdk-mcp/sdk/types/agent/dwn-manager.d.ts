import { GenericMessage, PrivateKeySigner, RecordsWriteMessage, Signer, UnionMessageReply } from '@abaxxtech/id';
import { DidResolver } from '../dids/index.js';
import { Readable } from 'readable-stream';
import { Dwn, EventsGet, RecordsRead, MessagesGet, RecordsWrite, RecordsQuery, RecordsDelete, ProtocolsQuery, ProtocolsConfigure } from '@abaxxtech/id';
import type { DwnResponse, ProcessDwnRequest, SendDwnRequest, IDManagedAgent } from './types/agent.js';
export type GeneralJws = {
    payload: string;
    signatures: SignatureEntry[];
};
export type SignatureEntry = {
    protected: string;
    signature: string;
};
export type RecordsWriteAuthorizationPayload = {
    recordId: string;
    contextId?: string;
    descriptorCid: string;
    attestationCid?: string;
    encryptionCid?: string;
};
export type DwnManagerOptions = {
    agent?: IDManagedAgent;
    dwn: Dwn;
};
export type DwnManagerCreateOptions = {
    agent?: IDManagedAgent;
    dataPath?: string;
    didResolver?: DidResolver;
    dwn?: Dwn;
};
export declare class DwnManager {
    /**
     * Holds the instance of a `IDManagedAgent` that represents the current
     * execution context for the `KeyManager`. This agent is utilized
     * to interact with other agent components. It's vital
     * to ensure this instance is set to correctly contextualize
     * operations within the broader agent framework.
     */
    private _agent?;
    private _dwn;
    constructor(options: DwnManagerOptions);
    /**
     * Constructs a Signer for the connected did.
     *
     * @param author - The DID.
     * @returns A promise that resolves to the result.
     */
    getSigner(author: string): Promise<Signer>;
    /**
     * Constructs a Private Key Signer for a did.
     *
     * @param author - The DID Object.
     * @returns A promise that resolves to the result.
     */
    getPrivateKeySigner(author: any): Promise<PrivateKeySigner[]>;
    /**
     * Retrieves the `IDManagedAgent` execution context.
     * If the `agent` instance proprety is undefined, it will throw an error.
     *
     * @returns The `IDManagedAgent` instance that represents the current execution
     * context.
     *
     * @throws Will throw an error if the `agent` instance property is undefined.
     */
    get agent(): IDManagedAgent;
    set agent(agent: IDManagedAgent);
    get dwn(): Dwn;
    static create(options?: DwnManagerCreateOptions): Promise<DwnManager>;
    processRequest(request: ProcessDwnRequest): Promise<DwnResponse>;
    sendRequest(request: SendDwnRequest): Promise<DwnResponse>;
    private messageDataToBase64;
    private constructDwnMessage;
    private getAuthorSigningKeyId;
    private constructDwnSigner;
    private getDwnMessage;
    /**
     * ADDED TO GET SYNC WORKING
     * - createMessage()
     * - processMessage()
     * - writePrunedRecord()
     */
    createMessage(options: {
        author: string;
        messageOptions: unknown;
        messageType: string;
    }): Promise<EventsGet | MessagesGet | RecordsRead | RecordsQuery | RecordsWrite | RecordsDelete | ProtocolsQuery | ProtocolsConfigure>;
    /**
     * Writes a pruned initial `RecordsWrite` to a DWN without needing to supply associated data.
     * Note: This method should ONLY be used by a {@link SyncManager} implementation.
     *
     * @param options.targetDid - DID of the DWN tenant to write the pruned RecordsWrite to.
     * @returns DWN reply containing the status of processing request.
     */
    writePrunedRecord(options: {
        targetDid: string;
        message: RecordsWriteMessage;
    }): Promise<GenericMessageReply>;
    processMessage(options: {
        targetDid: string;
        message: GenericMessage;
        dataStream?: Readable;
    }): Promise<UnionMessageReply>;
}
type GenericMessageReply = {
    status: Status;
};
type Status = {
    code: number;
    detail: string;
};
export {};
//# sourceMappingURL=dwn-manager.d.ts.map