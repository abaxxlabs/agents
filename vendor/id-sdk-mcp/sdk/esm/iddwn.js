var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import * as Sdk from '@abaxxtech/id';
import ms from 'ms';
import { IDUserAgent } from './user-agent/index.js';
import { DwnApi } from './dwn-api.js';
import { DidApi } from './did-api.js';
import { getServiceDwnEndpoints } from './service-options.js';
import { DidKeyMethod, DidDhtMethod, DidIonMethod, DidDht } from './dids/index.js';
import { Metadata } from './interfaces/metadata.js';
import { Queue } from './interfaces/queue.js';
import { Services } from './interfaces/services.js';
import { Transactions } from './interfaces/transactions.js';
import { Jose } from './crypto/index.js';
import { VcApi } from './vc-api.js';
import { Jws } from '@abaxxtech/id';
export class IDDwn {
    constructor(options) {
        const { agent, connectedDid } = options;
        this.agent = agent;
        this.connectedDid = connectedDid;
        this.did = new DidApi({ agent, connectedDid });
        this.dwn = new DwnApi({ agent, connectedDid });
        this.metadata = new Metadata({ agent, connectedDid });
        this.protocol = Sdk;
        this.queue = new Queue({ agent, connectedDid });
        this.services = new Services({ agent, connectedDid });
        this.transactions = new Transactions({ agent, connectedDid });
        this.utils = { DidKeyMethod, DidDhtMethod, DidIonMethod, Jose, Jws };
        this.vc = new VcApi({ agent, connectedDid, dwnApi: this.dwn });
    }
    /**
     * Connects to a {@link IDAgent}. Defaults to creating a local {@link IDUserAgent}
     * if one isn't provided.
     *
     * @param options - optional overrides
     * @returns
     */
    static connect(options = {}) {
        var _a, _b, _c;
        return __awaiter(this, void 0, void 0, function* () {
            let { agent, appData, connectedDid, sync, serviceOptions, passphrase, didMethod, queueWhenOffline, flushWhenOnline } = options;
            // Default to 'ion' for backward compatibility
            didMethod = didMethod !== null && didMethod !== void 0 ? didMethod : 'ion';
            // Apply did:dht relay target globally.
            // Priority:
            // 1) Explicit serviceOptions.dhtRelayUrl
            // 2) Derive from first configured DWN endpoint as `${endpoint}/dht`
            if (serviceOptions === null || serviceOptions === void 0 ? void 0 : serviceOptions.dhtRelayUrl) {
                DidDht.setRelayUrl(serviceOptions.dhtRelayUrl.replace(/\/+$/, ''));
            }
            else if ((_a = serviceOptions === null || serviceOptions === void 0 ? void 0 : serviceOptions.dwnEndpoints) === null || _a === void 0 ? void 0 : _a.length) {
                const derivedRelayUrl = `${serviceOptions.dwnEndpoints[0].replace(/\/+$/, '')}/dht`;
                DidDht.setRelayUrl(derivedRelayUrl);
            }
            if (agent === undefined) {
                // Create the agent (with outbox when queueWhenOffline is not disabled).
                const userAgent = yield IDUserAgent.create({ appData, queueWhenOffline });
                agent = userAgent;
                if (passphrase === undefined) {
                    passphrase = 'insecure-static-phrase';
                }
                // Start the agent.
                yield userAgent.start({ passphrase });
                // Connect attempt failed or was rejected so fallback to local user agent.
                // if (IDUserAgent.isConnected() === false) {
                // Query the Agent's DWN tenant for identity records.
                const identities = yield userAgent.identityManager.list();
                const storedIdentities = identities.length;
                // If an existing identity is not found, create a new one.
                if (storedIdentities === 0) {
                    // Generate DID options based on the selected method
                    let didOptions;
                    switch (didMethod) {
                        case 'dht': {
                            const serviceEndpointNodes = (_b = serviceOptions === null || serviceOptions === void 0 ? void 0 : serviceOptions.dwnEndpoints) !== null && _b !== void 0 ? _b : yield getServiceDwnEndpoints();
                            didOptions = yield DidDhtMethod.generateDwnOptions({ serviceEndpointNodes });
                            break;
                        }
                        case 'ion': {
                            const serviceEndpointNodes = (_c = serviceOptions === null || serviceOptions === void 0 ? void 0 : serviceOptions.dwnEndpoints) !== null && _c !== void 0 ? _c : yield getServiceDwnEndpoints();
                            didOptions = yield DidIonMethod.generateDwnOptions({ serviceEndpointNodes });
                            break;
                        }
                        case 'key':
                            // did:key doesn't need service endpoints or key generation options
                            didOptions = {};
                            break;
                        default:
                            throw new Error(`Unsupported DID method: ${didMethod}`);
                    }
                    // Generate a new Identity for the end-user.
                    const identity = yield userAgent.identityManager.create({
                        name: 'Default',
                        didMethod,
                        didOptions,
                        kms: 'local'
                    });
                    /** Import the Identity metadata to the User Agent's tenant so that it can be restored
                     * on subsequent launches or page reloads. */
                    yield userAgent.identityManager.import({ identity, context: userAgent.agentDid });
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
                    yield userAgent.syncManager.registerIdentity({ did: connectedDid });
                    // Enable sync using the specified interval or default.
                    sync !== null && sync !== void 0 ? sync : (sync = '1m');
                    userAgent.syncManager.startSync({ interval: ms(sync) })
                        .catch((error) => __awaiter(this, void 0, void 0, function* () {
                        console.error(`Sync failed: ${error}`);
                    }));
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
        });
    }
    /**
     * Run outbox drain then one sync cycle (push + pull). Use when back online
     * to flush queued sends and sync immediately without waiting for the next interval.
     */
    flushOutboxAndSync() {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
            const managed = this.agent;
            if (managed.outbox)
                yield managed.outbox.drain();
            if ((_a = managed.syncManager) === null || _a === void 0 ? void 0 : _a.runNow)
                yield managed.syncManager.runNow();
        });
    }
}
//# sourceMappingURL=iddwn.js.map