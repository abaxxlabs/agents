import type { DidMetadata, PortableDid, DidMethodApi, DidIonCreateOptions, DidKeyCreateOptions, DidDhtCreateOptions } from '../dids/index.js';
import type { ManagedDidStore } from './store-managed-did.js';
import type { DidRequest, DidResponse, IDManagedAgent } from './types/agent.js';
export type CreateDidMethodOptions = {
    dht: DidDhtCreateOptions;
    ion: DidIonCreateOptions;
    key: DidKeyCreateOptions;
};
export type CreateDidOptions<M extends keyof CreateDidMethodOptions> = CreateDidMethodOptions[M] & {
    method: M;
    alias?: string;
    context?: string;
    kms?: string;
    metadata?: DidMetadata;
};
export declare enum DidMessage {
    Create = "Create",
    Resolve = "Resolve"
}
export type ImportDidOptions = {
    alias?: string;
    context?: string;
    did: PortableDid;
    kms?: string;
};
export interface ManagedDid extends PortableDid {
    /**
     * An alternate identifier used to identify the DID.
     * This property can be used to associate a DID with an external identifier.
     */
    alias?: string;
    /**
     * DID Method name.
     */
    method: string;
}
export type DidManagerOptions = {
    agent?: IDManagedAgent;
    didMethods: DidMethodApi[];
    store?: ManagedDidStore;
};
export type DidIonGenerateKeySetOptions = {};
export type DidKeyGenerateKeySetOptions = {};
export type GenerateKeySetOptions = {
    ion: DidIonGenerateKeySetOptions;
    key: DidKeyGenerateKeySetOptions;
};
export declare class DidManager {
    /**
     * Holds the instance of a `IDManagedAgent` that represents the current
     * execution context for the `KeyManager`. This agent is utilized
     * to interact with other agent components. It's vital
     * to ensure this instance is set to correctly contextualize
     * operations within the broader agent framework.
     */
    private _agent?;
    private _didMethods;
    private _store;
    constructor(options: DidManagerOptions);
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
    create<M extends keyof CreateDidMethodOptions>(options: CreateDidOptions<M>): Promise<ManagedDid>;
    getDefaultSigningKey(options: {
        did: string;
    }): Promise<string | undefined>;
    get(options: {
        didRef: string;
        context?: string;
    }): Promise<ManagedDid | undefined>;
    import(options: ImportDidOptions): Promise<ManagedDid>;
    /**
     * Retrieves a `DidMethodApi` instance associated with a specific method
     * name. This method uses the method name to access the `didMethods` map
     * and returns the corresponding `DidMethodApi` instance. If a method
     * name is provided that does not exist within the `didMethods` map, it
     * will throw an error.
     *
     * @param methodName - A string representing the name of the method for
     * which the corresponding `DidMethodApi` instance is to be retrieved.
     *
     * @returns The `DidMethodApi` instance that corresponds to the provided
     * method name. If no `DidMethodApi` instance corresponds to the provided
     * method name, an error is thrown.
     *
     * @throws Will throw an error if the provided method name does not
     * correspond to any `DidMethodApi` instance within the `didMethods` map.
     */
    private getMethod;
    private importOrGetKeySet;
    processRequest(request: DidRequest): Promise<DidResponse>;
    /**
     * Set the KeyManager alias for each key to the DID primary ID.
     *
     * If defined, use the `canonicalId` as the primary ID for the
     * DID subject. Otherwise, use the `id` property from the topmost
     * map of the DID document.
     *
     * @see {@link https://www.w3.org/TR/did-core/#did-subject | DID Subject}
     * @see {@link https://www.w3.org/TR/did-core/#dfn-canonicalid | DID Document Metadata}
     */
    private updateKeySet;
}
//# sourceMappingURL=did-manager.d.ts.map