import type { IDAgent } from './agent/index.js';
import type { ProtocolsConfigure } from '@abaxxtech/id';
/**
 * The protocol configure message carries the protocol definition and is used
 * to setup the protocol.
 *
 * @beta
 */
export type ProtocolsConfigureMessage = ProtocolsConfigure['message'];
/**
 * Metadata of the protocol
 *
 * @beta
 */
type ProtocolMetadata = {
    author: string;
    messageCid?: string;
};
/**
 * The Protocol API abstraction class. It's used to represent and retrieve a protocol and
 * also to install (send) protocols to other DIDs.
 *
 * @beta
 */
export declare class Protocol {
    private _agent;
    private _metadata;
    private _protocolsConfigureMessage;
    /**
     * The protocol definition: types, structure and publish status
     */
    get definition(): import("@abaxxtech/id").ProtocolDefinition;
    constructor(agent: IDAgent, protocolsConfigureMessage: ProtocolsConfigureMessage, metadata: ProtocolMetadata);
    /**
     * Returns the protocol as a JSON object.
     */
    toJSON(): import("@abaxxtech/id").ProtocolsConfigureMessage;
    /**
     * Sends the protocol to a remote DWN by specifying their DID
     * @param target - the DID to send the protocol to
     * @returns the status of the send protocols request
     */
    send(target: string): Promise<{
        status: {
            code: number;
            detail: string;
        };
    }>;
}
export {};
//# sourceMappingURL=protocol.d.ts.map