"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.IDUserAgent = void 0;
// import { DateSort, DataStream } from '@abaxxtech/id';
// import { DwnApi } from '../dwn-api.js';
const index_js_1 = require("../common/index.js");
const index_js_2 = require("../crypto/index.js");
const index_js_3 = require("../dids/index.js");
const level_1 = require("level");
const index_js_4 = require("../agent/index.js");
let connected = false;
class IDUserAgent {
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
    static async create(options = {}) {
        let { agentDid, appData, didManager, didResolver, dwnManager, identityManager, keyManager, rpcClient, syncManager, queueWhenOffline } = options;
        if (agentDid === undefined) {
            // An Agent DID was not specified, so set to empty string.
            agentDid = '';
        }
        if (appData === undefined) {
            /** A custom AppDataStore implementation was not specified, so
             * instantiate a LevelDB backed secure AppDataVault. */
            appData = new index_js_4.AppDataVault({
                store: new index_js_1.LevelStore('data/AGENT/APPDATA')
            });
        }
        if (didManager === undefined) {
            /** A custom DidManager implementation was not specified, so
             * instantiate a default that uses a DWN-backed store. */
            didManager = new index_js_4.DidManager({
                didMethods: [index_js_3.DidIonMethod, index_js_3.DidKeyMethod, index_js_3.DidDhtMethod],
                store: new index_js_4.DidStoreDwn()
            });
        }
        if (didResolver === undefined) {
            /** A custom DidManager implementation was not specified, so
             * instantiate a default that uses a DWN-backed store and
             * LevelDB-backed resolution cache. */
            didResolver = new index_js_3.DidResolver({
                cache: new index_js_3.DidResolverCacheLevel(),
                didResolvers: [index_js_3.DidIonMethod, index_js_3.DidKeyMethod, index_js_3.DidDhtMethod]
            });
        }
        if (dwnManager === undefined) {
            /** A custom DwnManager implementation was not specified, so
             * instantiate a default. */
            dwnManager = await index_js_4.DwnManager.create({ didResolver });
        }
        if (identityManager === undefined) {
            /** A custom IdentityManager implementation was not specified, so
             * instantiate a default that uses a DWN-backed store. */
            identityManager = new index_js_4.IdentityManager({
                store: new index_js_4.IdentityStoreDwn()
            });
        }
        if (keyManager === undefined) {
            /** A custom KeyManager implementation was not specified, so
             * instantiate a default with KMSs that use a DWN-backed store. */
            const localKmsDwn = new index_js_4.LocalKms({
                kmsName: 'local',
                keyStore: new index_js_4.KeyStoreDwn({ schema: 'https://abaxx.tech/schemas/dwn/kms-key' }),
                privateKeyStore: new index_js_4.PrivateKeyStoreDwn()
            });
            const localKmsMemory = new index_js_4.LocalKms({
                kmsName: 'memory'
            });
            keyManager = new index_js_4.KeyManager({
                kms: {
                    local: localKmsDwn,
                    memory: localKmsMemory
                },
                store: new index_js_4.KeyStoreDwn({ schema: 'https://abaxx.tech/schemas/dwn/managed-key' })
            });
        }
        if (rpcClient === undefined) {
            // A custom RPC Client implementation was not specified, so
            // instantiate a default.
            rpcClient = new index_js_4.IDRpcClient();
        }
        if (syncManager === undefined) {
            // A custom SyncManager implementation was not specified, so
            // instantiate a LevelDB-backed default. When queueWhenOffline is enabled,
            // use a shared Level so Outbox and SyncManager share the same store root.
            if (queueWhenOffline !== false) {
                const agentDb = new level_1.Level('data/AGENT');
                syncManager = new index_js_4.SyncManagerLevel({ db: agentDb });
                options.outbox = new index_js_4.Outbox({ db: agentDb });
            }
            else {
                syncManager = new index_js_4.SyncManagerLevel();
            }
        }
        else if (queueWhenOffline !== false && options.outbox === undefined) {
            options.outbox = new index_js_4.Outbox();
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
    }
    static isConnected() {
        return connected;
    }
    async firstLaunch() {
        // Check whether data vault is already initialized.
        const { initialized } = await this.appData.getStatus();
        return initialized === false;
    }
    /** Executed once the first time the Agent is launched.
     * The passphrase should be input by the end-user. */
    async initialize(options) {
        const { passphrase } = options;
        // Generate an Ed25519 key pair for the Agent.
        const agentKeyPair = await new index_js_2.EdDsaAlgorithm().generateKey({
            algorithm: { name: 'EdDSA', namedCurve: 'Ed25519' },
            extractable: true,
            keyUsages: ['sign', 'verify']
        });
        /** Initialize the AppDataStore with the Agent's
         * private key and passphrase, which also unlocks the data vault. */
        await this.appData.initialize({
            passphrase: passphrase,
            keyPair: agentKeyPair,
        });
    }
    async processDidRequest(request) {
        switch (request.messageType) {
            case index_js_4.DidMessage.Resolve: {
                const { didUrl, resolutionOptions } = request.messageOptions;
                const result = await this.didResolver.resolve(didUrl, resolutionOptions);
                return { result };
            }
            default: {
                return this.didManager.processRequest(request);
            }
        }
    }
    async processDwnRequest(request) {
        return this.dwnManager.processRequest(request);
    }
    async processVcRequest(_request) {
        throw new Error('Not implemented');
    }
    async sendDidRequest(_request) {
        throw new Error('Not implemented');
    }
    async sendDwnRequest(request) {
        return this.dwnManager.sendRequest(request);
    }
    async sendVcRequest(_request) {
        throw new Error('Not implemented');
    }
    async start(options) {
        const { passphrase } = options;
        if (await this.firstLaunch()) {
            // 1A. Agent's first launch so initialize.
            await this.initialize({ passphrase });
        }
        else {
            // 1B. Agent was previously initialized.
            // Unlock the data vault and cache the vault unlock key (VUK) in memory.
            await this.appData.unlock({ passphrase });
        }
        // 2. Set the Agent's root did:key identifier.
        this.agentDid = await this.appData.getDid();
        // 3. Import the Agent's private key into the KeyManager.
        const defaultSigningKey = (0, index_js_4.cryptoToPortableKeyPair)({
            cryptoKeyPair: {
                privateKey: await this.appData.getPrivateKey(),
                publicKey: await this.appData.getPublicKey()
            },
            keyData: {
                alias: await this.didManager.getDefaultSigningKey({ did: this.agentDid }),
                kms: 'memory'
            }
        });
        // Import the Agent's signing key pair to the in-memory KMS key stores.
        await this.keyManager.setDefaultSigningKey({ key: defaultSigningKey });
    }
}
exports.IDUserAgent = IDUserAgent;
//# sourceMappingURL=index.js.map