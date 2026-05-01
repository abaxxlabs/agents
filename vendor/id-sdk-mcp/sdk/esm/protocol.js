var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
/**
 * The Protocol API abstraction class. It's used to represent and retrieve a protocol and
 * also to install (send) protocols to other DIDs.
 *
 * @beta
 */
export class Protocol {
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
    send(target) {
        return __awaiter(this, void 0, void 0, function* () {
            const { reply } = yield this._agent.sendDwnRequest({
                author: this._metadata.author,
                messageCid: this._metadata.messageCid,
                messageType: 'ProtocolsConfigure',
                target: target,
            });
            return { status: reply.status };
        });
    }
}
//# sourceMappingURL=protocol.js.map