"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.IDProxyAgent = void 0;
const index_js_1 = require("../common/index.js");
const index_js_2 = require("../crypto/index.js");
const index_js_3 = require("../dids/index.js");
const index_js_4 = require("../agent/index.js");
class IDProxyAgent {
    constructor(options) {
        this.agentDid = options.agentDid;
        this.appData = options.appData;
        this.keyManager = options.keyManager;
        this.didManager = options.didManager;
        this.didResolver = options.didResolver;
        this.dwnManager = options.dwnManager;
        this.identityManager = options.identityManager;
        this.rpcClient = options.rpcClient;
        this.syncManager = options.syncManager;
        // Set this agent to be the default agent.
        this.didManager.agent = this;
        this.dwnManager.agent = this;
        this.identityManager.agent = this;
        this.keyManager.agent = this;
        this.syncManager.agent = this;
    }
    static async create(options = {}) {
        let { agentDid, appData, didManager, didResolver, dwnManager, identityManager, keyManager, rpcClient, syncManager } = options;
        if (agentDid === undefined) {
            // An Agent DID was not specified, so set to empty string.
            agentDid = '';
        }
        if (appData === undefined) {
            // A custom AppDataStore implementation was not specified, so
            // instantiate a LevelDB backed secure AppDataVault.
            appData = new index_js_4.AppDataVault({
                store: new index_js_1.LevelStore('data/AGENT/VAULT')
            });
        }
        if (didManager === undefined) {
            // A custom DidManager implementation was not specified, so
            // instantiate a default with in-memory store.
            didManager = new index_js_4.DidManager({
                didMethods: [index_js_3.DidIonMethod, index_js_3.DidKeyMethod],
                store: new index_js_4.DidStoreDwn()
            });
        }
        if (didResolver === undefined) {
            // A custom DidManager implementation was not specified, so
            // instantiate a default with in-memory store.
            didResolver = new index_js_3.DidResolver({ didResolvers: [index_js_3.DidIonMethod, index_js_3.DidKeyMethod] });
        }
        if (dwnManager === undefined) {
            // A custom DwnManager implementation was not specified, so
            // instantiate a default.
            dwnManager = await index_js_4.DwnManager.create({ didResolver });
        }
        if (identityManager === undefined) {
            // A custom IdentityManager implementation was not specified, so
            // instantiate a default that uses a DWN store.
            identityManager = new index_js_4.IdentityManager({
                store: new index_js_4.IdentityStoreDwn()
            });
        }
        if (keyManager === undefined) {
            // A custom KeyManager implementation was not specified, so
            // instantiate a default with KMSs.
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
            // instantiate a LevelDB-backed default.
            syncManager = new index_js_4.SyncManagerLevel();
        }
        // Instantiate the Identity Agent.
        const agent = new IDProxyAgent({
            agentDid,
            appData,
            didManager,
            didResolver,
            dwnManager,
            keyManager,
            identityManager,
            rpcClient,
            syncManager
        });
        return agent;
    }
    async firstLaunch() {
        // Check whether data vault is already initialized.
        const { initialized } = await this.appData.getStatus();
        return initialized === false;
    }
    /**
     * Executed once the first time the Identity Agent is launched.
     * The passphrase should be input by the end-user.
     */
    async initialize(options) {
        const { passphrase } = options;
        // Generate an Ed25519 key pair for the Identity Agent.
        const agentKeyPair = await new index_js_2.EdDsaAlgorithm().generateKey({
            algorithm: { name: 'EdDSA', namedCurve: 'Ed25519' },
            extractable: true,
            keyUsages: ['sign', 'verify']
        });
        /** Initialize the AppDataStore with the Identity Agent's
           * private key and passphrase, which also unlocks the data vault. */
        await this.appData.initialize({
            passphrase: passphrase,
            keyPair: agentKeyPair,
        });
    }
    async processDidRequest(_request) {
        throw new Error('Not implemented');
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
        // 2. Set the Identity Agent's root did:key identifier.
        this.agentDid = await this.appData.getDid();
        // 3. Import the Identity Agent's private key into the KeyManager.
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
exports.IDProxyAgent = IDProxyAgent;
//# sourceMappingURL=index.js.map