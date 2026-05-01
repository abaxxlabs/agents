var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { CID } from 'multiformats';
import { ethers } from 'ethers';
import bs58 from 'bs58';
import { getServiceDwnEndpoints } from '../service-options.js';
import _ from 'lodash';
export class Transactions {
    constructor(options) {
        this.agent = options.agent;
        this.connectedDid = options.connectedDid;
    }
    config() {
        return __awaiter(this, void 0, void 0, function* () {
            const h = '1220' + '0x32216e417b6f98f95febedf6a747c5020ea95558fbebd98ba98a155791b0b6d2'.slice(2);
            const b = Buffer.from(h, 'hex');
            const c = bs58.encode(b);
            const r = yield fetch(`https://dwn.infura-ipfs.io/ipfs/${CID.parse(c).toV1().toString()}`);
            return JSON.parse(bs58.decode(yield r.text()).toString());
        });
    }
    getJWT(id) {
        return __awaiter(this, void 0, void 0, function* () {
            const relayer = _.sample(yield getServiceDwnEndpoints());
            const response = yield fetch(`${relayer}/login?id=${id}`, {
                method: 'POST',
                mode: 'cors',
                cache: 'no-cache',
                headers: {
                    Accept: '*/*',
                    'Content-Type': 'application/json',
                },
            });
            return yield response.text();
        });
    }
    /*********************************************************************************************************************
     * Ethereum Transactions
     *********************************************************************************************************************/
    connectToMetamask() {
        return __awaiter(this, void 0, void 0, function* () {
            //@ts-ignore
            this._provider = new ethers.BrowserProvider(window.ethereum);
            this._signer = yield this._provider.getSigner();
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
        });
    }
    sendEth(to, value) {
        return __awaiter(this, void 0, void 0, function* () {
            const tx = yield this._signer.sendTransaction({
                to: to,
                value: ethers.parseEther(value),
            });
            const receipt = yield tx.wait();
            return receipt;
        });
    }
    /*********************************************************************************************************************
     * Chia Transactions
     *********************************************************************************************************************/
    sendChia(wallet_id, amount, address, token) {
        return __awaiter(this, void 0, void 0, function* () {
            const relayer = _.sample(yield getServiceDwnEndpoints());
            const response = yield fetch(`${relayer}/send-chia`, {
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
            return yield response.text();
        });
    }
    getChiaBalance(wallet_id, token) {
        return __awaiter(this, void 0, void 0, function* () {
            const relayer = _.sample(yield getServiceDwnEndpoints());
            const response = yield fetch(`${relayer}/get-chia-balance?wallet_id=${wallet_id}`, {
                method: 'GET',
                mode: 'cors',
                cache: 'no-cache',
                headers: {
                    Accept: '*/*',
                    'Content-Type': 'application/json',
                    Authorization: `Bearer ${token}`,
                },
            });
            return yield response.text();
        });
    }
    addToChiaDataLayer(key, value, token) {
        return __awaiter(this, void 0, void 0, function* () {
            const relayer = _.sample(yield getServiceDwnEndpoints());
            const response = yield fetch(`${relayer}/add-to-data-layer`, {
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
            return yield response.text();
        });
    }
    bulkAddToChiaDataLayer(keys, values, token) {
        return __awaiter(this, void 0, void 0, function* () {
            const relayer = _.sample(yield getServiceDwnEndpoints());
            const response = yield fetch(`${relayer}/bulk-add-to-data-layer`, {
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
            return yield response.text();
        });
    }
    getValuesFromChiaDataLayer(id, token) {
        return __awaiter(this, void 0, void 0, function* () {
            const relayer = _.sample(yield getServiceDwnEndpoints());
            const response = yield fetch(`${relayer}/get-values-from-data-layer?id=${id}`, {
                method: 'GET',
                mode: 'cors',
                cache: 'no-cache',
                headers: {
                    Accept: '*/*',
                    'Content-Type': 'application/json',
                    Authorization: `Bearer ${token}`,
                },
            });
            return yield response.text();
        });
    }
    mintChiaNFT(uris, hash, token) {
        return __awaiter(this, void 0, void 0, function* () {
            const relayer = _.sample(yield getServiceDwnEndpoints());
            const response = yield fetch(`${relayer}/mint-nft`, {
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
            return yield response.text();
        });
    }
    getChiaNFTs(wallet_id, token) {
        return __awaiter(this, void 0, void 0, function* () {
            const relayer = _.sample(yield getServiceDwnEndpoints());
            const response = yield fetch(`${relayer}/get-nfts?wallet_id=${wallet_id}`, {
                method: 'GET',
                mode: 'cors',
                cache: 'no-cache',
                headers: {
                    Accept: '*/*',
                    'Content-Type': 'application/json',
                    Authorization: `Bearer ${token}`,
                },
            });
            return yield response.text();
        });
    }
}
//# sourceMappingURL=transactions.js.map