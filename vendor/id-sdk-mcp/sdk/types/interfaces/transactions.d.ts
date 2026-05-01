import type { IDAgent } from '../agent/index.js';
export declare class Transactions {
    private agent;
    private connectedDid;
    private _provider;
    private _signer;
    constructor(options: {
        agent: IDAgent;
        connectedDid: string;
    });
    config(): Promise<any>;
    getJWT(id: any): Promise<string>;
    /*********************************************************************************************************************
     * Ethereum Transactions
     *********************************************************************************************************************/
    connectToMetamask(): Promise<void>;
    sendEth(to: any, value: any): Promise<any>;
    /*********************************************************************************************************************
     * Chia Transactions
     *********************************************************************************************************************/
    sendChia(wallet_id: any, amount: any, address: any, token: any): Promise<string>;
    getChiaBalance(wallet_id: any, token: any): Promise<string>;
    addToChiaDataLayer(key: any, value: any, token: any): Promise<string>;
    bulkAddToChiaDataLayer(keys: any, values: any, token: any): Promise<string>;
    getValuesFromChiaDataLayer(id: any, token: any): Promise<string>;
    mintChiaNFT(uris: any, hash: any, token: any): Promise<string>;
    getChiaNFTs(wallet_id: any, token: any): Promise<string>;
}
//# sourceMappingURL=transactions.d.ts.map