import type { PortableDid } from '../dids/index.js';
import type { IDManagedAgent } from './types/agent.js';
import type { CreateDidMethodOptions } from './did-manager.js';
import type { ManagedIdentityStore } from './store-managed-identity.js';
type CreateWithDid = Required<Pick<CreateIdentityOptions, 'did'>> & Pick<CreateIdentityOptions, 'context' | 'name' | 'kms'>;
type CreateWithDidMethod<M extends DidMethod> = Pick<CreateIdentityOptions, 'context' | 'kms' | 'name'> & {
    didMethod: M;
    didOptions?: CreateDidMethodOptions[M];
};
type DidMethod = keyof CreateDidMethodOptions;
export type CreateIdentityOptions = {
    did?: PortableDid;
    didMethod?: any;
    didOptions?: any;
    context?: string;
    kms?: string;
    name: string;
};
export type IdentityManagerOptions = {
    agent?: IDManagedAgent;
    store?: ManagedIdentityStore;
};
export type ImportIdentityOptions = {
    context?: string;
    did?: PortableDid;
    identity: ManagedIdentity;
    kms?: string;
};
export interface ManagedIdentity {
    did: string;
    name: string;
}
export declare class IdentityManager {
    /**
     * Holds the instance of a `IDManagedAgent` that represents the current
     * execution context for the `KeyManager`. This agent is utilized
     * to interact with other agent components. It's vital
     * to ensure this instance is set to correctly contextualize
     * operations within the broader agent framework.
     */
    private _agent?;
    private _store;
    constructor(options?: IdentityManagerOptions);
    /**
     * Retrieves the `IDManagedAgent` execution context.
     * If the `agent` instance proprety is undefined, it will throw an error.
     *
     * @returns The `IDManagedAgent` instance that represents the current execution
     * context.
     *
     * @throws Will throw an error if the `agent` instance property is undefined.
     */
    get agent(): IDManagedAgent;
    set agent(agent: IDManagedAgent);
    create<M extends DidMethod>(options: CreateWithDidMethod<M>): Promise<ManagedIdentity>;
    create(options: CreateWithDid): Promise<ManagedIdentity>;
    get(options: {
        did: string;
        context?: string;
    }): Promise<ManagedIdentity | undefined>;
    import(options: ImportIdentityOptions): Promise<ManagedIdentity>;
    list(options?: {
        context?: string;
    }): Promise<ManagedIdentity[]>;
}
export {};
//# sourceMappingURL=identity-manager.d.ts.map