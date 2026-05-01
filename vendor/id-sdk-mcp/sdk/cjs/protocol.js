"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Protocol = void 0;
/**
 * The Protocol API abstraction class. It's used to represent and retrieve a protocol and
 * also to install (send) protocols to other DIDs.
 *
 * @beta
 */
class Protocol {
    /**
     * The protocol definition: types, structure and publish status
     */
    get definition() {
        return this._protocolsConfigureMessage.descriptor.definition;
    }
    constructor(agent, protocolsConfigureMessage, metadata) {
        this._agent = agent;
        this._metadata = metadata;
        this._protocolsConfigureMessage = protocolsConfigureMessage;
    }
    /**
     * Returns the protocol as a JSON object.
     */
    toJSON() {
        return this._protocolsConfigureMessage;
    }
    /**
     * Sends the protocol to a remote DWN by specifying their DID
     * @param target - the DID to send the protocol to
     * @returns the status of the send protocols request
     */
    async send(target) {
        const { reply } = await this._agent.sendDwnRequest({
            author: this._metadata.author,
            messageCid: this._metadata.messageCid,
            messageType: 'ProtocolsConfigure',
            target: target,
        });
        return { status: reply.status };
    }
}
exports.Protocol = Protocol;
//# sourceMappingURL=protocol.js.map