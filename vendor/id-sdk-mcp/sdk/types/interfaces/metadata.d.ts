import type { IDAgent } from '../agent/index.js';
export declare class Metadata {
    private agent;
    private connectedDid;
    private _ipfs;
    constructor(options: {
        agent: IDAgent;
        connectedDid: string;
    });
    config(): Promise<any>;
    aliasGet(alias: any): Promise<string>;
    aliasSet(alias: any, did: any, metadata?: {
        VerifiableCredentials: any[];
    }): Promise<string>;
    aliasPut(alias: any, did: any, metadata?: {
        VerifiableCredentials: any[];
    }): Promise<string>;
    save(data: any): Promise<string>;
    get(id: any): Promise<any>;
    saveJson(jsonData: any): Promise<string>;
    getJson(id: any): Promise<any>;
    encrypt(publicKey: any, input: any): Promise<string>;
    decrypt(privateKey: any, output: any): Promise<string>;
    private getBytes32FromIpfsHash;
    private getIpfsHashFromBytes32;
}
//# sourceMappingURL=metadata.d.ts.map