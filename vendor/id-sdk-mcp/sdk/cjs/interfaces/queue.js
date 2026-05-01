"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Queue = void 0;
const libp2p_1 = require("libp2p");
const circuit_relay_1 = require("libp2p/circuit-relay");
const libp2p_gossipsub_1 = require("@chainsafe/libp2p-gossipsub");
const identify_1 = require("libp2p/identify");
const kad_dht_1 = require("@libp2p/kad-dht");
const mplex_1 = require("@libp2p/mplex");
const libp2p_noise_1 = require("@chainsafe/libp2p-noise");
const pubsub_js_1 = require("pubsub-js");
const webrtc_star_1 = require("@libp2p/webrtc-star");
const libp2p_yamux_1 = require("@chainsafe/libp2p-yamux");
class Queue {
    constructor(options) {
        this.agent = options.agent;
        this.connectedDid = options.connectedDid;
        this._star = (0, webrtc_star_1.webRTCStar)();
    }
    async createPeer() {
        return await (0, libp2p_1.createLibp2p)({
            addresses: {
                listen: [
                    // '/dns4/star.abaxx.id/tcp/443/wss/p2p-webrtc-star/',
                    '/dns4/star.comtrol.io/tcp/443/wss/p2p-webrtc-star/',
                ],
            },
            transports: [
                this._star.transport,
                (0, circuit_relay_1.circuitRelayTransport)({
                    discoverRelays: 1,
                }),
            ],
            connectionEncryption: [
                //@ts-ignore
                (0, libp2p_noise_1.noise)(), // elliptic curve Diffie-Hellman key exchange using Curve e25519
            ],
            streamMuxers: [
                //@ts-ignore
                (0, libp2p_yamux_1.yamux)(), (0, mplex_1.mplex)(),
            ],
            peerDiscovery: [
                this._star.discovery,
            ],
            services: {
                //@ts-ignore
                pubsub: (0, libp2p_gossipsub_1.gossipsub)({
                    allowPublishToZeroPeers: true,
                    enabled: true,
                    emitSelf: true,
                }),
                identify: (0, identify_1.identifyService)(),
                dht: (0, kad_dht_1.kadDHT)({
                    clientMode: true,
                }),
            },
        });
    }
    async send(node, topic, message) {
        var _a, _b;
        (_b = (_a = node === null || node === void 0 ? void 0 : node.services) === null || _a === void 0 ? void 0 : _a.pubsub) === null || _b === void 0 ? void 0 : _b.publish(topic, new TextEncoder().encode(message)).catch((err) => {
            return { ok: false, error: err.message, timestsamp: new Date().getTime() };
        });
        return { ok: true, timestsamp: new Date().getTime() };
    }
    async publish(topic, message, relayers = []) {
        const response = await fetch(`${relayers[0]}/publish`, {
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
        pubsub_js_1.PubSub.publish(topic, message);
        return await response.text();
    }
    async subscribe(topic, cb) {
        const relaySubscriber = (msg, data) => {
            if (msg === topic) {
                cb(data);
            }
        };
        const subscriber = pubsub_js_1.PubSub.subscribe(topic, relaySubscriber);
        return subscriber;
    }
    async unsubscribe(topic) {
        pubsub_js_1.PubSub.unsubscribe(topic);
    }
}
exports.Queue = Queue;
//# sourceMappingURL=queue.js.map