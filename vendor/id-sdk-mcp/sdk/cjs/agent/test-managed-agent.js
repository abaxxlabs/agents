"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.TestManagedAgent = void 0;
const level_1 = require("level");
const index_js_1 = require("../crypto/index.js");
const id_1 = require("@abaxxtech/id");
const index_js_2 = require("../common/index.js");
const index_js_3 = require("../dids/index.js");
const kms_local_js_1 = require("./kms-local.js");
const did_manager_js_1 = require("./did-manager.js");
const dwn_manager_js_1 = require("./dwn-manager.js");
const key_manager_js_1 = require("./key-manager.js");
const rpc_client_js_1 = require("./rpc-client.js");
const app_data_store_js_1 = require("./app-data-store.js");
const sync_manager_js_1 = require("./sync-manager.js");
const utils_js_1 = require("./utils.js");
const store_managed_did_js_1 = require("./store-managed-did.js");
const identity_manager_js_1 = require("./identity-manager.js");
const store_managed_identity_js_1 = require("./store-managed-identity.js");
const store_managed_key_js_1 = require("./store-managed-key.js");
class TestManagedAgent {
    constructor(options) {
        this.agent = options.agent;
        this.agentStores = options.agentStores;
        this.appDataStore = options.appDataStore;
        this.didResolverCache = options.didResolverCache;
        this.dwn = options.dwn;
        this.dwnDataStore = options.dwnDataStore;
        this.dwnEventLog = options.dwnEventLog;
        this.dwnMessageStore = options.dwnMessageStore;
        this.syncStore = options.syncStore;
    }
    async clearStorage() {
        this.agent.agentDid = undefined;
        await this.appDataStore.clear();
        await this.didResolverCache.clear();
        await this.dwnDataStore.clear();
        await this.dwnEventLog.clear();
        await this.dwnMessageStore.clear();
        await this.syncStore.clear();
        /** Easiest way to start with fresh in-memory stores is to
         * re-instantiate all of the managed agent components */
        if (this.agentStores === 'memory') {
            const { didManager, identityManager, keyManager } = TestManagedAgent.useMemoryStorage({ agent: this.agent });
            this.agent.didManager = didManager;
            this.agent.identityManager = identityManager;
            this.agent.keyManager = keyManager;
        }
    }
    async closeStorage() {
        await this.appDataStore.close();
        await this.didResolverCache.close();
        await this.dwnDataStore.close();
        await this.dwnEventLog.close();
        await this.dwnMessageStore.close();
        await this.syncStore.close();
    }
    static async create(options) {
        let { agentClass, agentStores, testDataLocation } = options;
        agentStores !== null && agentStores !== void 0 ? agentStores : (agentStores = 'memory');
        testDataLocation !== null && testDataLocation !== void 0 ? testDataLocation : (testDataLocation = '__TESTDATA__');
        const testDataPath = (path) => `${testDataLocation}/${path}`;
        const { appData, appDataStore, didManager, didResolverCache, identityManager, keyManager } = (agentStores === 'memory')
            ? TestManagedAgent.useMemoryStorage()
            : TestManagedAgent.useDiskStorage({ testDataLocation });
        // Instantiate DID resolver.
        const didMethodApis = [index_js_3.DidIonMethod, index_js_3.DidKeyMethod];
        const didResolver = new index_js_3.DidResolver({
            cache: didResolverCache,
            didResolvers: didMethodApis
        });
        // Instantiate custom stores to use with DWN instance.
        const dwnDataStore = new id_1.DataStoreLevel({ blockstoreLocation: testDataPath('DWN_DATASTORE') });
        const dwnEventLog = new id_1.EventLogLevel({ location: testDataPath('DWN_EVENTLOG') });
        const dwnMessageStore = new id_1.MessageStoreLevel({
            blockstoreLocation: testDataPath('DWN_MESSAGESTORE'),
            indexLocation: testDataPath('DWN_MESSAGEINDEX')
        });
        // Instantiate custom DWN instance.
        const dwn = await id_1.Dwn.create({
            eventLog: dwnEventLog,
            dataStore: dwnDataStore,
            // @ts-expect-error because the DidResolver implementation doesn't have the dump() method.
            didResolver: didResolver,
            messageStore: dwnMessageStore
        });
        // Instantiate a DwnManager using the custom DWN instance.
        const dwnManager = new dwn_manager_js_1.DwnManager({ dwn });
        // Instantiate an RPC Client.
        const rpcClient = new rpc_client_js_1.IDRpcClient();
        // Instantiate a custom SyncManager and LevelDB-backed store.
        const syncStore = new level_1.Level(testDataPath('SYNC_STORE'));
        const syncManager = new sync_manager_js_1.SyncManagerLevel({ db: syncStore });
        const agent = new agentClass({
            agentDid: '',
            appData,
            didManager,
            didResolver,
            dwnManager,
            identityManager,
            keyManager,
            rpcClient,
            syncManager
        });
        return new TestManagedAgent({
            agent,
            agentStores,
            appDataStore,
            didResolverCache,
            dwn,
            dwnDataStore,
            dwnEventLog,
            dwnMessageStore,
            syncStore,
        });
    }
    async createAgentDid() {
        // Create an a DID and key set for the Agent.
        const agentDid = await index_js_3.DidKeyMethod.create({ keyAlgorithm: 'Ed25519' });
        const privateCryptoKey = await index_js_1.Jose.jwkToCryptoKey({ key: agentDid.keySet.verificationMethodKeys[0].privateKeyJwk });
        const publicCryptoKey = await index_js_1.Jose.jwkToCryptoKey({ key: agentDid.keySet.verificationMethodKeys[0].publicKeyJwk });
        const agentSigningKey = { privateKey: privateCryptoKey, publicKey: publicCryptoKey };
        // Set the DID as the default signing key.
        const alias = await this.agent.didManager.getDefaultSigningKey({ did: agentDid.did });
        const defaultSigningKey = (0, utils_js_1.cryptoToPortableKeyPair)({ cryptoKeyPair: agentSigningKey, keyData: { alias, kms: 'memory' } });
        await this.agent.keyManager.setDefaultSigningKey({ key: defaultSigningKey });
        // Set the DID as the Agent's DID.
        this.agent.agentDid = agentDid.did;
    }
    async createIdentity(options) {
        // Default to generating Ed25519 keys.
        const { keyAlgorithm, testDwnUrls } = options;
        const didOptions = await index_js_3.DidIonMethod.generateDwnOptions({
            signingKeyAlgorithm: keyAlgorithm,
            serviceEndpointNodes: testDwnUrls
        });
        // Create a PortableDid.
        const did = await index_js_3.DidIonMethod.create(Object.assign({ anchor: false }, didOptions));
        // Create a ManagedIdentity.
        const identity = {
            did: did.did,
            name: 'Test'
        };
        return { did, identity };
    }
    static useDiskStorage(options) {
        const { agent, testDataLocation } = options;
        const testDataPath = (path) => `${testDataLocation}/${path}`;
        const appDataStore = new index_js_2.LevelStore(testDataPath('APPDATA'));
        const appData = new app_data_store_js_1.AppDataVault({
            keyDerivationWorkFactor: 1,
            store: appDataStore
        });
        const didManager = new did_manager_js_1.DidManager({
            agent,
            didMethods: [index_js_3.DidIonMethod, index_js_3.DidKeyMethod],
            store: new store_managed_did_js_1.DidStoreDwn()
        });
        const didResolverCache = new index_js_3.DidResolverCacheLevel({
            location: testDataPath('DID_RESOLVERCACHE')
        });
        const identityManager = new identity_manager_js_1.IdentityManager({
            agent,
            store: new store_managed_identity_js_1.IdentityStoreDwn()
        });
        const localKmsDwn = new kms_local_js_1.LocalKms({
            agent,
            kmsName: 'local',
            keyStore: new store_managed_key_js_1.KeyStoreDwn({ schema: 'https://abaxx.tech/schemas/dwn/kms-key' }),
            privateKeyStore: new store_managed_key_js_1.PrivateKeyStoreDwn()
        });
        const localKmsMemory = new kms_local_js_1.LocalKms({
            agent,
            kmsName: 'memory'
        });
        const keyManager = new key_manager_js_1.KeyManager({
            agent,
            kms: {
                local: localKmsDwn,
                memory: localKmsMemory
            },
            store: new store_managed_key_js_1.KeyStoreDwn({ schema: 'https://abaxx.tech/schemas/dwn/managed-key' })
        });
        return { appData, appDataStore, didManager, didResolverCache, identityManager, keyManager };
    }
    static useMemoryStorage(options) {
        const { agent } = options !== null && options !== void 0 ? options : {};
        const appDataStore = new index_js_2.MemoryStore();
        const appData = new app_data_store_js_1.AppDataVault({
            keyDerivationWorkFactor: 1,
            store: appDataStore
        });
        const didManager = new did_manager_js_1.DidManager({
            agent,
            didMethods: [index_js_3.DidIonMethod, index_js_3.DidKeyMethod],
            store: new store_managed_did_js_1.DidStoreMemory()
        });
        const didResolverCache = new index_js_2.MemoryStore();
        const identityManager = new identity_manager_js_1.IdentityManager({
            agent,
            store: new store_managed_identity_js_1.IdentityStoreMemory()
        });
        const localKmsDwn = new kms_local_js_1.LocalKms({
            agent,
            kmsName: 'local',
            keyStore: new store_managed_key_js_1.KeyStoreMemory(),
            privateKeyStore: new store_managed_key_js_1.PrivateKeyStoreMemory()
        });
        const localKmsMemory = new kms_local_js_1.LocalKms({
            agent,
            kmsName: 'memory'
        });
        const keyManager = new key_manager_js_1.KeyManager({
            agent,
            kms: {
                local: localKmsDwn,
                memory: localKmsMemory
            },
            store: new store_managed_key_js_1.KeyStoreMemory()
        });
        return { appData, appDataStore, didManager, didResolverCache, identityManager, keyManager };
    }
}
exports.TestManagedAgent = TestManagedAgent;
//# sourceMappingURL=test-managed-agent.js.map