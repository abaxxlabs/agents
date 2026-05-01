"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.IdentityManager = void 0;
const store_managed_identity_js_1 = require("./store-managed-identity.js");
class IdentityManager {
    constructor(options) {
        const { agent, store } = options !== null && options !== void 0 ? options : {};
        this._agent = agent;
        this._store = store !== null && store !== void 0 ? store : new store_managed_identity_js_1.IdentityStoreMemory();
    }
    /**
     * Retrieves the `IDManagedAgent` execution context.
     * If the `agent` instance proprety is undefined, it will throw an error.
     *
     * @returns The `IDManagedAgent` instance that represents the current execution
     * context.
     *
     * @throws Will throw an error if the `agent` instance property is undefined.
     */
    get agent() {
        if (this._agent === undefined) {
            throw new Error('IdentityManager: Unable to determine agent execution context.');
        }
        return this._agent;
    }
    set agent(agent) {
        this._agent = agent;
    }
    async create(options) {
        let { context, did, didMethod, didOptions, kms, name } = options;
        if (!(didMethod ? !did : did)) {
            throw new Error(`Either 'did' or 'didMethod' must be defined, but not both.`);
        }
        let managedDid;
        // Get the agent instance.
        const agent = this.agent;
        if (didMethod) {
            // Create new DID and generate key set.
            managedDid = await agent.didManager.create(Object.assign({ method: didMethod, context, kms }, didOptions));
        }
        else if (did) {
            // Import given DID and key set.
            managedDid = await agent.didManager.import({ did, context, kms });
        }
        if (managedDid === undefined) {
            throw new Error('IdentityManager: Unable to generate or import DID.');
        }
        // Create a ManagedIdentity.
        const identity = {
            did: managedDid.did,
            name: name
        };
        /** If context is undefined, then the Identity will be stored under the
         * tenant of the created DID. Otherwise, the Identity records will
         * be stored under the tenant of the specified context. */
        context !== null && context !== void 0 ? context : (context = identity.did);
        // Store the ManagedIdentity in the store.
        await this._store.importIdentity({ identity, agent, context });
        return identity;
    }
    async get(options) {
        const { context, did } = options;
        const identity = this._store.getIdentity({ did, agent: this.agent, context });
        return identity;
    }
    async import(options) {
        let { context, did, identity, kms } = options;
        // Get the agent instance.
        const agent = this.agent;
        // If provided, import the given DID and key set.
        if (did) {
            await agent.didManager.import({ did, context, kms });
        }
        /** If context is undefined, then the Identity will be stored under the
         * tenant of the imported DID. Otherwise, the Identity record will
         * be stored under the tenant of the specified context. */
        context !== null && context !== void 0 ? context : (context = identity.did);
        // Store the ManagedIdentity in the store.
        await this._store.importIdentity({ identity, agent, context });
        return identity;
    }
    async list(options) {
        const { context } = options !== null && options !== void 0 ? options : {};
        const identities = this._store.listIdentities({ agent: this.agent, context });
        return identities;
    }
}
exports.IdentityManager = IdentityManager;
//# sourceMappingURL=identity-manager.js.map