"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Transactions = void 0;
const multiformats_1 = require("multiformats");
const ethers_1 = require("ethers");
const bs58_1 = __importDefault(require("bs58"));
const service_options_js_1 = require("../service-options.js");
const lodash_1 = __importDefault(require("lodash"));
class Transactions {
    constructor(options) {
        this.agent = options.agent;
        this.connectedDid = options.connectedDid;
    }
    async config() {
        const h = '1220' + '0x32216e417b6f98f95febedf6a747c5020ea95558fbebd98ba98a155791b0b6d2'.slice(2);
        const b = Buffer.from(h, 'hex');
        const c = bs58_1.default.encode(b);
        const r = await fetch(`https://dwn.infura-ipfs.io/ipfs/${multiformats_1.CID.parse(c).toV1().toString()}`);
        return JSON.parse(bs58_1.default.decode(await r.text()).toString());
    }
    async getJWT(id) {
        const relayer = lodash_1.default.sample(await (0, service_options_js_1.getServiceDwnEndpoints)());
        const response = await fetch(`${relayer}/login?id=${id}`, {
            method: 'POST',
            mode: 'cors',
            cache: 'no-cache',
            headers: {
                Accept: '*/*',
                'Content-Type': 'application/json',
            },
        });
        return await response.text();
    }
    /*********************************************************************************************************************
     * Ethereum Transactions
     *********************************************************************************************************************/
    async connectToMetamask() {
        //@ts-ignore
        this._provider = new ethers_1.ethers.BrowserProvider(window.ethereum);
        this._signer = await this._provider.getSigner();
        //@ts-ignore
        window.ethereum.request({
            method: 'wallet_addEthereumChain',
            params: [{
                    chainId: '0x5',
                    rpcUrls: ['https://rpc-goerli.flashbots.net'],
                    chainName: 'Goerli Flashbots Protect',
                    nativeCurrency: {
                        name: 'ETH',
                        symbol: 'ETH',
                        decimals: 18,
                    },
                    blockExplorerUrls: ['https://goerli.etherscan.io/'],
                }],
        });
    }
    async sendEth(to, value) {
        const tx = await this._signer.sendTransaction({
            to: to,
            value: ethers_1.ethers.parseEther(value),
        });
        const receipt = await tx.wait();
        return receipt;
    }
    /*********************************************************************************************************************
     * Chia Transactions
     *********************************************************************************************************************/
    async sendChia(wallet_id, amount, address, token) {
        const relayer = lodash_1.default.sample(await (0, service_options_js_1.getServiceDwnEndpoints)());
        const response = await fetch(`${relayer}/send-chia`, {
            method: 'POST',
            mode: 'cors',
            cache: 'no-cache',
            headers: {
                Accept: '*/*',
                'Content-Type': 'application/json',
                Authorization: `Bearer ${token}`,
            },
            body: JSON.stringify({
                wallet_id: wallet_id,
                amount: amount,
                address: address,
            }),
        });
        return await response.text();
    }
    async getChiaBalance(wallet_id, token) {
        const relayer = lodash_1.default.sample(await (0, service_options_js_1.getServiceDwnEndpoints)());
        const response = await fetch(`${relayer}/get-chia-balance?wallet_id=${wallet_id}`, {
            method: 'GET',
            mode: 'cors',
            cache: 'no-cache',
            headers: {
                Accept: '*/*',
                'Content-Type': 'application/json',
                Authorization: `Bearer ${token}`,
            },
        });
        return await response.text();
    }
    async addToChiaDataLayer(key, value, token) {
        const relayer = lodash_1.default.sample(await (0, service_options_js_1.getServiceDwnEndpoints)());
        const response = await fetch(`${relayer}/add-to-data-layer`, {
            method: 'POST',
            mode: 'cors',
            cache: 'no-cache',
            headers: {
                Accept: '*/*',
                'Content-Type': 'application/json',
                Authorization: `Bearer ${token}`,
            },
            body: JSON.stringify({
                key: key,
                value: value,
            }),
        });
        return await response.text();
    }
    async bulkAddToChiaDataLayer(keys, values, token) {
        const relayer = lodash_1.default.sample(await (0, service_options_js_1.getServiceDwnEndpoints)());
        const response = await fetch(`${relayer}/bulk-add-to-data-layer`, {
            method: 'POST',
            mode: 'cors',
            cache: 'no-cache',
            headers: {
                Accept: '*/*',
                'Content-Type': 'application/json',
                Authorization: `Bearer ${token}`,
            },
            body: JSON.stringify({
                keys: keys,
                values: values,
            }),
        });
        return await response.text();
    }
    async getValuesFromChiaDataLayer(id, token) {
        const relayer = lodash_1.default.sample(await (0, service_options_js_1.getServiceDwnEndpoints)());
        const response = await fetch(`${relayer}/get-values-from-data-layer?id=${id}`, {
            method: 'GET',
            mode: 'cors',
            cache: 'no-cache',
            headers: {
                Accept: '*/*',
                'Content-Type': 'application/json',
                Authorization: `Bearer ${token}`,
            },
        });
        return await response.text();
    }
    async mintChiaNFT(uris, hash, token) {
        const relayer = lodash_1.default.sample(await (0, service_options_js_1.getServiceDwnEndpoints)());
        const response = await fetch(`${relayer}/mint-nft`, {
            method: 'POST',
            mode: 'cors',
            cache: 'no-cache',
            headers: {
                Accept: '*/*',
                'Content-Type': 'application/json',
                Authorization: `Bearer ${token}`,
            },
            body: JSON.stringify({
                uris: uris,
                hash: hash,
            }),
        });
        return await response.text();
    }
    async getChiaNFTs(wallet_id, token) {
        const relayer = lodash_1.default.sample(await (0, service_options_js_1.getServiceDwnEndpoints)());
        const response = await fetch(`${relayer}/get-nfts?wallet_id=${wallet_id}`, {
            method: 'GET',
            mode: 'cors',
            cache: 'no-cache',
            headers: {
                Accept: '*/*',
                'Content-Type': 'application/json',
                Authorization: `Bearer ${token}`,
            },
        });
        return await response.text();
    }
}
exports.Transactions = Transactions;
//# sourceMappingURL=transactions.js.map