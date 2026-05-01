var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { Level } from 'level';
import { Jose } from '../crypto/index.js';
import { Dwn, MessageStoreLevel, DataStoreLevel, EventLogLevel } from '@dwn-protocol/id';
import { LevelStore, MemoryStore } from '../common/index.js';
import { DidIonMethod, DidKeyMethod, DidResolver, DidResolverCacheLevel } from '../dids/index.js';
import { LocalKms } from './kms-local.js';
import { DidManager } from './did-manager.js';
import { DwnManager } from './dwn-manager.js';
import { KeyManager } from './key-manager.js';
import { IDRpcClient } from './rpc-client.js';
import { AppDataVault } from './app-data-store.js';
import { SyncManagerLevel } from './sync-manager.js';
import { cryptoToPortableKeyPair } from './utils.js';
import { DidStoreDwn, DidStoreMemory } from './store-managed-did.js';
import { IdentityManager } from './identity-manager.js';
import { IdentityStoreDwn, IdentityStoreMemory } from './store-managed-identity.js';
import { KeyStoreDwn, KeyStoreMemory, PrivateKeyStoreDwn, PrivateKeyStoreMemory } from './store-managed-key.js';
export class TestManagedAgent {
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
    clearStorage() {
        return __awaiter(this, void 0, void 0, function* () {
            this.agent.agentDid = undefined;
            yield this.appDataStore.clear();
            yield this.didResolverCache.clear();
            yield this.dwnDataStore.clear();
            yield this.dwnEventLog.clear();
            yield this.dwnMessageStore.clear();
            yield this.syncStore.clear();
            /** Easiest way to start with fresh in-memory stores is to
             * re-instantiate all of the managed agent components */
            if (this.agentStores === 'memory') {
                const { didManager, identityManager, keyManager } = TestManagedAgent.useMemoryStorage({ agent: this.agent });
                this.agent.didManager = didManager;
                this.agent.identityManager = identityManager;
                this.agent.keyManager = keyManager;
            }
        });
    }
    closeStorage() {
        return __awaiter(this, void 0, void 0, function* () {
            yield this.appDataStore.close();
            yield this.didResolverCache.close();
            yield this.dwnDataStore.close();
            yield this.dwnEventLog.close();
            yield this.dwnMessageStore.close();
            yield this.syncStore.close();
        });
    }
    static create(options) {
        return __awaiter(this, void 0, void 0, function* () {
            let { agentClass, agentStores, testDataLocation } = options;
            agentStores !== null && agentStores !== void 0 ? agentStores : (agentStores = 'memory');
            testDataLocation !== null && testDataLocation !== void 0 ? testDataLocation : (testDataLocation = '__TESTDATA__');
            const testDataPath = (path) => `${testDataLocation}/${path}`;
            const { appData, appDataStore, didManager, didResolverCache, identityManager, keyManager } = (agentStores === 'memory')
                ? TestManagedAgent.useMemoryStorage()
                : TestManagedAgent.useDiskStorage({ testDataLocation });
            // Instantiate DID resolver.
            const didMethodApis = [DidIonMethod, DidKeyMethod];
            const didResolver = new DidResolver({
                cache: didResolverCache,
                didResolvers: didMethodApis
            });
            // Instantiate custom stores to use with DWN instance.
            const dwnDataStore = new DataStoreLevel({ blockstoreLocation: testDataPath('DWN_DATASTORE') });
            const dwnEventLog = new EventLogLevel({ location: testDataPath('DWN_EVENTLOG') });
            const dwnMessageStore = new MessageStoreLevel({
                blockstoreLocation: testDataPath('DWN_MESSAGESTORE'),
                indexLocation: testDataPath('DWN_MESSAGEINDEX')
            });
            // Instantiate custom DWN instance.
            const dwn = yield Dwn.create({
                eventLog: dwnEventLog,
                dataStore: dwnDataStore,
                // @ts-expect-error because the DidResolver implementation doesn't have the dump() method.
                didResolver: didResolver,
                messageStore: dwnMessageStore
            });
            // Instantiate a DwnManager using the custom DWN instance.
            const dwnManager = new DwnManager({ dwn });
            // Instantiate an RPC Client.
            const rpcClient = new IDRpcClient();
            // Instantiate a custom SyncManager and LevelDB-backed store.
            const syncStore = new Level(testDataPath('SYNC_STORE'));
            const syncManager = new SyncManagerLevel({ db: syncStore });
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
        });
    }
    createAgentDid() {
        return __awaiter(this, void 0, void 0, function* () {
            // Create an a DID and key set for the Agent.
            const agentDid = yield DidKeyMethod.create({ keyAlgorithm: 'Ed25519' });
            const privateCryptoKey = yield Jose.jwkToCryptoKey({ key: agentDid.keySet.verificationMethodKeys[0].privateKeyJwk });
            const publicCryptoKey = yield Jose.jwkToCryptoKey({ key: agentDid.keySet.verificationMethodKeys[0].publicKeyJwk });
            const agentSigningKey = { privateKey: privateCryptoKey, publicKey: publicCryptoKey };
            // Set the DID as the default signing key.
            const alias = yield this.agent.didManager.getDefaultSigningKey({ did: agentDid.did });
            const defaultSigningKey = cryptoToPortableKeyPair({ cryptoKeyPair: agentSigningKey, keyData: { alias, kms: 'memory' } });
            yield this.agent.keyManager.setDefaultSigningKey({ key: defaultSigningKey });
            // Set the DID as the Agent's DID.
            this.agent.agentDid = agentDid.did;
        });
    }
    createIdentity(options) {
        return __awaiter(this, void 0, void 0, function* () {
            // Default to generating Ed25519 keys.
            const { keyAlgorithm, testDwnUrls } = options;
            const didOptions = yield DidIonMethod.generateDwnOptions({
                signingKeyAlgorithm: keyAlgorithm,
                serviceEndpointNodes: testDwnUrls
            });
            // Create a PortableDid.
            const did = yield DidIonMethod.create(Object.assign({ anchor: false }, didOptions));
            // Create a ManagedIdentity.
            const identity = {
                did: did.did,
                name: 'Test'
            };
            return { did, identity };
        });
    }
    static useDiskStorage(options) {
        const { agent, testDataLocation } = options;
        const testDataPath = (path) => `${testDataLocation}/${path}`;
        const appDataStore = new LevelStore(testDataPath('APPDATA'));
        const appData = new AppDataVault({
            keyDerivationWorkFactor: 1,
            store: appDataStore
        });
        const didManager = new DidManager({
            agent,
            didMethods: [DidIonMethod, DidKeyMethod],
            store: new DidStoreDwn()
        });
        const didResolverCache = new DidResolverCacheLevel({
            location: testDataPath('DID_RESOLVERCACHE')
        });
        const identityManager = new IdentityManager({
            agent,
            store: new IdentityStoreDwn()
        });
        const localKmsDwn = new LocalKms({
            agent,
            kmsName: 'local',
            keyStore: new KeyStoreDwn({ schema: 'https://abaxx.tech/schemas/dwn/kms-key' }),
            privateKeyStore: new PrivateKeyStoreDwn()
        });
        const localKmsMemory = new LocalKms({
            agent,
            kmsName: 'memory'
        });
        const keyManager = new KeyManager({
            agent,
            kms: {
                local: localKmsDwn,
                memory: localKmsMemory
            },
            store: new KeyStoreDwn({ schema: 'https://abaxx.tech/schemas/dwn/managed-key' })
        });
        return { appData, appDataStore, didManager, didResolverCache, identityManager, keyManager };
    }
    static useMemoryStorage(options) {
        const { agent } = options !== null && options !== void 0 ? options : {};
        const appDataStore = new MemoryStore();
        const appData = new AppDataVault({
            keyDerivationWorkFactor: 1,
            store: appDataStore
        });
        const didManager = new DidManager({
            agent,
            didMethods: [DidIonMethod, DidKeyMethod],
            store: new DidStoreMemory()
        });
        const didResolverCache = new MemoryStore();
        const identityManager = new IdentityManager({
            agent,
            store: new IdentityStoreMemory()
        });
        const localKmsDwn = new LocalKms({
            agent,
            kmsName: 'local',
            keyStore: new KeyStoreMemory(),
            privateKeyStore: new PrivateKeyStoreMemory()
        });
        const localKmsMemory = new LocalKms({
            agent,
            kmsName: 'memory'
        });
        const keyManager = new KeyManager({
            agent,
            kms: {
                local: localKmsDwn,
                memory: localKmsMemory
            },
            store: new KeyStoreMemory()
        });
        return { appData, appDataStore, didManager, didResolverCache, identityManager, keyManager };
    }
}
//# sourceMappingURL=test-managed-agent.js.map