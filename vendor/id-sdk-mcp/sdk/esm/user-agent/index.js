var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
// import { DateSort, DataStream } from '@abaxxtech/id';
// import { DwnApi } from '../dwn-api.js';
import { LevelStore } from '../common/index.js';
import { EdDsaAlgorithm } from '../crypto/index.js';
import { DidIonMethod, DidKeyMethod, DidResolverCacheLevel, DidResolver, DidDhtMethod } from '../dids/index.js';
import { Level } from 'level';
import { LocalKms, DidManager, DwnManager, KeyManager, DidStoreDwn, KeyStoreDwn, AppDataVault, IDRpcClient, IdentityManager, IdentityStoreDwn, Outbox, SyncManagerLevel, PrivateKeyStoreDwn, cryptoToPortableKeyPair, DidMessage, } from '../agent/index.js';
let connected = false;
export class IDUserAgent {
    constructor(options) {
        this.agentDid = options.agentDid;
        this.appData = options.appData;
        this.keyManager = options.keyManager;
        this.didManager = options.didManager;
        this.didResolver = options.didResolver;
        this.dwnManager = options.dwnManager;
        this.identityManager = options.identityManager;
        this.outbox = options.outbox;
        this.rpcClient = options.rpcClient;
        this.syncManager = options.syncManager;
        // Set this agent to be the default agent.
        this.didManager.agent = this;
        this.dwnManager.agent = this;
        this.identityManager.agent = this;
        this.keyManager.agent = this;
        this.syncManager.agent = this;
        if (this.outbox) {
            this.outbox.agent = this;
        }
    }
    static create(options = {}) {
        return __awaiter(this, void 0, void 0, function* () {
            let { agentDid, appData, didManager, didResolver, dwnManager, identityManager, keyManager, rpcClient, syncManager, queueWhenOffline } = options;
            if (agentDid === undefined) {
                // An Agent DID was not specified, so set to empty string.
                agentDid = '';
            }
            if (appData === undefined) {
                /** A custom AppDataStore implementation was not specified, so
                 * instantiate a LevelDB backed secure AppDataVault. */
                appData = new AppDataVault({
                    store: new LevelStore('data/AGENT/APPDATA')
                });
            }
            if (didManager === undefined) {
                /** A custom DidManager implementation was not specified, so
                 * instantiate a default that uses a DWN-backed store. */
                didManager = new DidManager({
                    didMethods: [DidIonMethod, DidKeyMethod, DidDhtMethod],
                    store: new DidStoreDwn()
                });
            }
            if (didResolver === undefined) {
                /** A custom DidManager implementation was not specified, so
                 * instantiate a default that uses a DWN-backed store and
                 * LevelDB-backed resolution cache. */
                didResolver = new DidResolver({
                    cache: new DidResolverCacheLevel(),
                    didResolvers: [DidIonMethod, DidKeyMethod, DidDhtMethod]
                });
            }
            if (dwnManager === undefined) {
                /** A custom DwnManager implementation was not specified, so
                 * instantiate a default. */
                dwnManager = yield DwnManager.create({ didResolver });
            }
            if (identityManager === undefined) {
                /** A custom IdentityManager implementation was not specified, so
                 * instantiate a default that uses a DWN-backed store. */
                identityManager = new IdentityManager({
                    store: new IdentityStoreDwn()
                });
            }
            if (keyManager === undefined) {
                /** A custom KeyManager implementation was not specified, so
                 * instantiate a default with KMSs that use a DWN-backed store. */
                const localKmsDwn = new LocalKms({
                    kmsName: 'local',
                    keyStore: new KeyStoreDwn({ schema: 'https://abaxx.tech/schemas/dwn/kms-key' }),
                    privateKeyStore: new PrivateKeyStoreDwn()
                });
                const localKmsMemory = new LocalKms({
                    kmsName: 'memory'
                });
                keyManager = new KeyManager({
                    kms: {
                        local: localKmsDwn,
                        memory: localKmsMemory
                    },
                    store: new KeyStoreDwn({ schema: 'https://abaxx.tech/schemas/dwn/managed-key' })
                });
            }
            if (rpcClient === undefined) {
                // A custom RPC Client implementation was not specified, so
                // instantiate a default.
                rpcClient = new IDRpcClient();
            }
            if (syncManager === undefined) {
                // A custom SyncManager implementation was not specified, so
                // instantiate a LevelDB-backed default. When queueWhenOffline is enabled,
                // use a shared Level so Outbox and SyncManager share the same store root.
                if (queueWhenOffline !== false) {
                    const agentDb = new Level('data/AGENT');
                    syncManager = new SyncManagerLevel({ db: agentDb });
                    options.outbox = new Outbox({ db: agentDb });
                }
                else {
                    syncManager = new SyncManagerLevel();
                }
            }
            else if (queueWhenOffline !== false && options.outbox === undefined) {
                options.outbox = new Outbox();
            }
            // Instantiate the Agent.
            const agent = new IDUserAgent({
                agentDid,
                appData,
                didManager,
                didResolver,
                dwnManager,
                keyManager,
                identityManager,
                outbox: options.outbox,
                rpcClient,
                syncManager
            });
            // connected = false;
            return agent;
        });
    }
    static isConnected() {
        return connected;
    }
    firstLaunch() {
        return __awaiter(this, void 0, void 0, function* () {
            // Check whether data vault is already initialized.
            const { initialized } = yield this.appData.getStatus();
            return initialized === false;
        });
    }
    /** Executed once the first time the Agent is launched.
     * The passphrase should be input by the end-user. */
    initialize(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const { passphrase } = options;
            // Generate an Ed25519 key pair for the Agent.
            const agentKeyPair = yield new EdDsaAlgorithm().generateKey({
                algorithm: { name: 'EdDSA', namedCurve: 'Ed25519' },
                extractable: true,
                keyUsages: ['sign', 'verify']
            });
            /** Initialize the AppDataStore with the Agent's
             * private key and passphrase, which also unlocks the data vault. */
            yield this.appData.initialize({
                passphrase: passphrase,
                keyPair: agentKeyPair,
            });
        });
    }
    processDidRequest(request) {
        return __awaiter(this, void 0, void 0, function* () {
            switch (request.messageType) {
                case DidMessage.Resolve: {
                    const { didUrl, resolutionOptions } = request.messageOptions;
                    const result = yield this.didResolver.resolve(didUrl, resolutionOptions);
                    return { result };
                }
                default: {
                    return this.didManager.processRequest(request);
                }
            }
        });
    }
    processDwnRequest(request) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.dwnManager.processRequest(request);
        });
    }
    processVcRequest(_request) {
        return __awaiter(this, void 0, void 0, function* () {
            throw new Error('Not implemented');
        });
    }
    sendDidRequest(_request) {
        return __awaiter(this, void 0, void 0, function* () {
            throw new Error('Not implemented');
        });
    }
    sendDwnRequest(request) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.dwnManager.sendRequest(request);
        });
    }
    sendVcRequest(_request) {
        return __awaiter(this, void 0, void 0, function* () {
            throw new Error('Not implemented');
        });
    }
    start(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const { passphrase } = options;
            if (yield this.firstLaunch()) {
                // 1A. Agent's first launch so initialize.
                yield this.initialize({ passphrase });
            }
            else {
                // 1B. Agent was previously initialized.
                // Unlock the data vault and cache the vault unlock key (VUK) in memory.
                yield this.appData.unlock({ passphrase });
            }
            // 2. Set the Agent's root did:key identifier.
            this.agentDid = yield this.appData.getDid();
            // 3. Import the Agent's private key into the KeyManager.
            const defaultSigningKey = cryptoToPortableKeyPair({
                cryptoKeyPair: {
                    privateKey: yield this.appData.getPrivateKey(),
                    publicKey: yield this.appData.getPublicKey()
                },
                keyData: {
                    alias: yield this.didManager.getDefaultSigningKey({ did: this.agentDid }),
                    kms: 'memory'
                }
            });
            // Import the Agent's signing key pair to the in-memory KMS key stores.
            yield this.keyManager.setDefaultSigningKey({ key: defaultSigningKey });
        });
    }
}
//# sourceMappingURL=index.js.map