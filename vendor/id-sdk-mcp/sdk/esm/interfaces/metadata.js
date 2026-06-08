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
import { Encoder, Encryption } from '@abaxxtech/id';
import bs58 from 'bs58';
import IPFS from 'ipfs-infura';
import { getServiceDwnEndpoints } from '../service-options.js';
import _ from 'lodash';
export class Metadata {
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
    aliasGet(alias) {
        return __awaiter(this, void 0, void 0, function* () {
            const relayer = _.sample(yield getServiceDwnEndpoints());
            const response = yield fetch(`${relayer}/did/${alias}`, {
                method: 'GET',
                mode: 'cors',
                cache: 'no-cache',
                headers: {
                    'Accept': '*/*',
                    'Content-Type': 'application/json',
                },
            });
            return yield response.text();
        });
    }
    aliasSet(alias, did, metadata = { VerifiableCredentials: [] }) {
        return __awaiter(this, void 0, void 0, function* () {
            const relayer = _.sample(yield getServiceDwnEndpoints());
            const response = yield fetch(`${relayer}/did`, {
                method: 'POST',
                mode: 'cors',
                cache: 'no-cache',
                headers: {
                    'Accept': '*/*',
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    alias,
                    did,
                    metadata,
                }),
            });
            return yield response.text();
        });
    }
    aliasPut(alias, did, metadata = { VerifiableCredentials: [] }) {
        return __awaiter(this, void 0, void 0, function* () {
            const relayer = _.sample(yield getServiceDwnEndpoints());
            const response = yield fetch(`${relayer}/did`, {
                method: 'PUT',
                mode: 'cors',
                cache: 'no-cache',
                headers: {
                    'Accept': '*/*',
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    alias,
                    did,
                    metadata,
                }),
            });
            return yield response.text();
        });
    }
    save(data) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const b = Buffer.from(data);
                const d = bs58.encode(b);
                this._ipfs = new IPFS(yield this.config());
                const cid = yield this._ipfs.add(d);
                this._ipfs = undefined;
                return this.getBytes32FromIpfsHash(cid.toString());
            }
            catch (e) {
                throw new Error('Failure to submit file to IPFS');
            }
        });
    }
    get(id) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const cid = this.getIpfsHashFromBytes32(id);
                const response = yield fetch(`https://dwn.infura-ipfs.io/ipfs/${CID.parse(cid).toV1().toString()}`);
                const text = yield response.text();
                return bs58.decode(text).toString();
            }
            catch (e) {
                throw new Error('Failure to get file from IPFS');
            }
        });
    }
    saveJson(jsonData) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                this._ipfs = new IPFS(yield this.config());
                const cid = yield this._ipfs.addJSON(jsonData);
                this._ipfs = undefined;
                return this.getBytes32FromIpfsHash(cid.toString());
            }
            catch (e) {
                throw new Error('Failure to submit file to IPFS');
            }
        });
    }
    getJson(id) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const cid = this.getIpfsHashFromBytes32(id);
                const response = yield fetch(`https://dwn.infura-ipfs.io/ipfs/${CID.parse(cid).toV1().toString()}`);
                const json = yield response.json();
                return json;
            }
            catch (e) {
                throw new Error('Failure to get file from IPFS');
            }
        });
    }
    encrypt(publicKey, input) {
        return __awaiter(this, void 0, void 0, function* () {
            let encryptionOutput = yield Encryption.eciesSecp256k1Encrypt(publicKey, input);
            return Buffer.from(Encoder.bytesToString(Encoder.objectToBytes(encryptionOutput))).toString('base64');
        });
    }
    decrypt(privateKey, output) {
        return __awaiter(this, void 0, void 0, function* () {
            let newOutput = {};
            let json = Buffer.from(output, 'base64').toString('ascii');
            Object.entries(JSON.parse(json)).forEach((entry) => {
                const [key, value] = entry;
                //@ts-ignore
                newOutput[key] = value.type == 'Buffer' ? Buffer.from(value.data) : value;
            });
            const decryptionInput = Object.assign({ privateKey }, newOutput);
            //@ts-ignore
            const decryptedPlaintext = yield Encryption.eciesSecp256k1Decrypt(decryptionInput);
            return new TextDecoder().decode(decryptedPlaintext);
        });
    }
    getBytes32FromIpfsHash(ipfsHash) {
        return ('0x' + bs58.decode(ipfsHash).slice(2).toString('hex'));
    }
    getIpfsHashFromBytes32(bytes32Hex) {
        const hashHex = '1220' + bytes32Hex.slice(2);
        const hashBytes = Buffer.from(hashHex, 'hex');
        const hashStr = bs58.encode(hashBytes);
        return hashStr;
    }
}
//# sourceMappingURL=metadata.js.map