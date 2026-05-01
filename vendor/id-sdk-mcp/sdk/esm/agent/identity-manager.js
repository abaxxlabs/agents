var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { IdentityStoreMemory } from './store-managed-identity.js';
export class IdentityManager {
    constructor(options) {
        const { agent, store } = options !== null && options !== void 0 ? options : {};
        this._agent = agent;
        this._store = store !== null && store !== void 0 ? store : new IdentityStoreMemory();
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
    create(options) {
        return __awaiter(this, void 0, void 0, function* () {
            let { context, did, didMethod, didOptions, kms, name } = options;
            if (!(didMethod ? !did : did)) {
                throw new Error(`Either 'did' or 'didMethod' must be defined, but not both.`);
            }
            let managedDid;
            // Get the agent instance.
            const agent = this.agent;
            if (didMethod) {
                // Create new DID and generate key set.
                managedDid = yield agent.didManager.create(Object.assign({ method: didMethod, context, kms }, didOptions));
            }
            else if (did) {
                // Import given DID and key set.
                managedDid = yield agent.didManager.import({ did, context, kms });
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
            yield this._store.importIdentity({ identity, agent, context });
            return identity;
        });
    }
    get(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const { context, did } = options;
            const identity = this._store.getIdentity({ did, agent: this.agent, context });
            return identity;
        });
    }
    import(options) {
        return __awaiter(this, void 0, void 0, function* () {
            let { context, did, identity, kms } = options;
            // Get the agent instance.
            const agent = this.agent;
            // If provided, import the given DID and key set.
            if (did) {
                yield agent.didManager.import({ did, context, kms });
            }
            /** If context is undefined, then the Identity will be stored under the
             * tenant of the imported DID. Otherwise, the Identity record will
             * be stored under the tenant of the specified context. */
            context !== null && context !== void 0 ? context : (context = identity.did);
            // Store the ManagedIdentity in the store.
            yield this._store.importIdentity({ identity, agent, context });
            return identity;
        });
    }
    list(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const { context } = options !== null && options !== void 0 ? options : {};
            const identities = this._store.listIdentities({ agent: this.agent, context });
            return identities;
        });
    }
}
//# sourceMappingURL=identity-manager.js.map