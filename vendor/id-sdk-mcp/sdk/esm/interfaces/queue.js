var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { createLibp2p } from 'libp2p';
import { circuitRelayTransport } from 'libp2p/circuit-relay';
import { gossipsub } from '@chainsafe/libp2p-gossipsub';
import { identifyService } from 'libp2p/identify';
import { kadDHT } from '@libp2p/kad-dht';
import { mplex } from '@libp2p/mplex';
import { noise } from '@chainsafe/libp2p-noise';
import { PubSub } from 'pubsub-js';
import { webRTCStar } from '@libp2p/webrtc-star';
import { yamux } from '@chainsafe/libp2p-yamux';
export class Queue {
    constructor(options) {
        this.agent = options.agent;
        this.connectedDid = options.connectedDid;
        this._star = webRTCStar();
    }
    createPeer() {
        return __awaiter(this, void 0, void 0, function* () {
            return yield createLibp2p({
                addresses: {
                    listen: [
                        // '/dns4/star.abaxx.id/tcp/443/wss/p2p-webrtc-star/',
                        '/dns4/star.comtrol.io/tcp/443/wss/p2p-webrtc-star/',
                    ],
                },
                transports: [
                    this._star.transport,
                    circuitRelayTransport({
                        discoverRelays: 1,
                    }),
                ],
                connectionEncryption: [
                    //@ts-ignore
                    noise(), // elliptic curve Diffie-Hellman key exchange using Curve e25519
                ],
                streamMuxers: [
                    //@ts-ignore
                    yamux(), mplex(),
                ],
                peerDiscovery: [
                    this._star.discovery,
                ],
                services: {
                    //@ts-ignore
                    pubsub: gossipsub({
                        allowPublishToZeroPeers: true,
                        enabled: true,
                        emitSelf: true,
                    }),
                    identify: identifyService(),
                    dht: kadDHT({
                        clientMode: true,
                    }),
                },
            });
        });
    }
    send(node, topic, message) {
        var _a, _b;
        return __awaiter(this, void 0, void 0, function* () {
            (_b = (_a = node === null || node === void 0 ? void 0 : node.services) === null || _a === void 0 ? void 0 : _a.pubsub) === null || _b === void 0 ? void 0 : _b.publish(topic, new TextEncoder().encode(message)).catch((err) => {
                return { ok: false, error: err.message, timestsamp: new Date().getTime() };
            });
            return { ok: true, timestsamp: new Date().getTime() };
        });
    }
    publish(topic, message, relayers = []) {
        return __awaiter(this, void 0, void 0, function* () {
            const response = yield fetch(`${relayers[0]}/publish`, {
                method: 'POST',
                mode: 'cors',
                cache: 'no-cache',
                headers: {
                    'Accept': '*/*',
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    topic,
                    message,
                }),
            });
            PubSub.publish(topic, message);
            return yield response.text();
        });
    }
    subscribe(topic, cb) {
        return __awaiter(this, void 0, void 0, function* () {
            const relaySubscriber = (msg, data) => {
                if (msg === topic) {
                    cb(data);
                }
            };
            const subscriber = PubSub.subscribe(topic, relaySubscriber);
            return subscriber;
        });
    }
    unsubscribe(topic) {
        return __awaiter(this, void 0, void 0, function* () {
            PubSub.unsubscribe(topic);
        });
    }
}
//# sourceMappingURL=queue.js.map