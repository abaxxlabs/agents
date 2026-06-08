"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.IDDwn = void 0;
const Sdk = __importStar(require("@abaxxtech/id"));
const ms_1 = __importDefault(require("ms"));
const index_js_1 = require("./user-agent/index.js");
const dwn_api_js_1 = require("./dwn-api.js");
const did_api_js_1 = require("./did-api.js");
const service_options_js_1 = require("./service-options.js");
const index_js_2 = require("./dids/index.js");
const metadata_js_1 = require("./interfaces/metadata.js");
const queue_js_1 = require("./interfaces/queue.js");
const services_js_1 = require("./interfaces/services.js");
const transactions_js_1 = require("./interfaces/transactions.js");
const index_js_3 = require("./crypto/index.js");
const vc_api_js_1 = require("./vc-api.js");
const id_1 = require("@abaxxtech/id");
class IDDwn {
    constructor(options) {
        const { agent, connectedDid } = options;
        this.agent = agent;
        this.connectedDid = connectedDid;
        this.did = new did_api_js_1.DidApi({ agent, connectedDid });
        this.dwn = new dwn_api_js_1.DwnApi({ agent, connectedDid });
        this.metadata = new metadata_js_1.Metadata({ agent, connectedDid });
        this.protocol = Sdk;
        this.queue = new queue_js_1.Queue({ agent, connectedDid });
        this.services = new services_js_1.Services({ agent, connectedDid });
        this.transactions = new transactions_js_1.Transactions({ agent, connectedDid });
        this.utils = { DidKeyMethod: index_js_2.DidKeyMethod, DidDhtMethod: index_js_2.DidDhtMethod, DidIonMethod: index_js_2.DidIonMethod, Jose: index_js_3.Jose, Jws: id_1.Jws };
        this.vc = new vc_api_js_1.VcApi({ agent, connectedDid, dwnApi: this.dwn });
    }
    /**
     * Connects to a {@link IDAgent}. Defaults to creating a local {@link IDUserAgent}
     * if one isn't provided.
     *
     * @param options - optional overrides
     * @returns
     */
    static async connect(options = {}) {
        var _a, _b;
        let { agent, appData, connectedDid, sync, serviceOptions, passphrase, didMethod, queueWhenOffline, flushWhenOnline } = options;
        // Default to 'ion' for backward compatibility
        didMethod = didMethod !== null && didMethod !== void 0 ? didMethod : 'ion';
        // Apply did:dht relay target globally.
        // Priority:
        // 1) Explicit serviceOptions.dhtRelayUrl
        // 2) Derive from first configured DWN endpoint as `${endpoint}/dht`
        if (serviceOptions === null || serviceOptions === void 0 ? void 0 : serviceOptions.dhtRelayUrl) {
            index_js_2.DidDht.setRelayUrl(serviceOptions.dhtRelayUrl.replace(/\/+$/, ''));
        }
        else if ((_a = serviceOptions === null || serviceOptions === void 0 ? void 0 : serviceOptions.dwnEndpoints) === null || _a === void 0 ? void 0 : _a.length) {
            const derivedRelayUrl = `${serviceOptions.dwnEndpoints[0].replace(/\/+$/, '')}/dht`;
            index_js_2.DidDht.setRelayUrl(derivedRelayUrl);
        }
        if (agent === undefined) {
            // Create the agent (with outbox when queueWhenOffline is not disabled).
            const userAgent = await index_js_1.IDUserAgent.create({ appData, queueWhenOffline });
            agent = userAgent;
            if (passphrase === undefined) {
                passphrase = 'insecure-static-phrase';
            }
            // Start the agent.
            await userAgent.start({ passphrase });
            // Connect attempt failed or was rejected so fallback to local user agent.
            // if (IDUserAgent.isConnected() === false) {
            // Query the Agent's DWN tenant for identity records.
            const identities = await userAgent.identityManager.list();
            const storedIdentities = identities.length;
            // If an existing identity is not found, create a new one.
            if (storedIdentities === 0) {
                // Use the specified DWN endpoints or get default relayer nodes.
                const serviceEndpointNodes = (_b = serviceOptions === null || serviceOptions === void 0 ? void 0 : serviceOptions.dwnEndpoints) !== null && _b !== void 0 ? _b : await (0, service_options_js_1.getServiceDwnEndpoints)();
                // Generate DID options based on the selected method
                let didOptions;
                switch (didMethod) {
                    case 'dht':
                        didOptions = await index_js_2.DidDhtMethod.generateDwnOptions({ serviceEndpointNodes });
                        break;
                    case 'ion':
                        didOptions = await index_js_2.DidIonMethod.generateDwnOptions({ serviceEndpointNodes });
                        break;
                    case 'key':
                        // did:key doesn't need service endpoints or key generation options
                        didOptions = {};
                        break;
                    default:
                        throw new Error(`Unsupported DID method: ${didMethod}`);
                }
                // Generate a new Identity for the end-user.
                const identity = await userAgent.identityManager.create({
                    name: 'Default',
                    didMethod,
                    didOptions,
                    kms: 'local'
                });
                /** Import the Identity metadata to the User Agent's tenant so that it can be restored
                 * on subsequent launches or page reloads. */
                await userAgent.identityManager.import({ identity, context: userAgent.agentDid });
                // Set the newly created identity as the connected DID.
                // connectedDid = restoreDid? restoreDid : identity.did;
                connectedDid = identity.did;
            }
            else {
                // An existing identity was found in the User Agent's tenant.
                const [identity] = identities;
                // Set the stored identity as the connected DID.
                // connectedDid = restoreDid? restoreDid : identity.did;
                connectedDid = identity.did;
            }
            // }
            // Enable sync, unless disabled.
            if (sync !== 'off') {
                // First, register the user identity for sync.
                await userAgent.syncManager.registerIdentity({ did: connectedDid });
                // Enable sync using the specified interval or default.
                sync !== null && sync !== void 0 ? sync : (sync = '1m');
                userAgent.syncManager.startSync({ interval: (0, ms_1.default)(sync) })
                    .catch(async (error) => {
                    console.error(`Sync failed: ${error}`);
                });
            }
        }
        const iddwn = new IDDwn({ agent, connectedDid });
        if (flushWhenOnline && typeof window !== 'undefined') {
            window.addEventListener('online', () => {
                iddwn.flushOutboxAndSync().catch((err) => {
                    console.error('flushOutboxAndSync on online:', err);
                });
            });
        }
        return { iddwn, did: connectedDid };
    }
    /**
     * Run outbox drain then one sync cycle (push + pull). Use when back online
     * to flush queued sends and sync immediately without waiting for the next interval.
     */
    async flushOutboxAndSync() {
        var _a;
        const managed = this.agent;
        if (managed.outbox)
            await managed.outbox.drain();
        if ((_a = managed.syncManager) === null || _a === void 0 ? void 0 : _a.runNow)
            await managed.syncManager.runNow();
    }
}
exports.IDDwn = IDDwn;
//# sourceMappingURL=iddwn.js.map