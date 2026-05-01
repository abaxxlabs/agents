"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Metadata = void 0;
const multiformats_1 = require("multiformats");
const id_1 = require("@dwn-protocol/id");
const bs58_1 = __importDefault(require("bs58"));
const ipfs_infura_1 = __importDefault(require("ipfs-infura"));
const service_options_js_1 = require("../service-options.js");
const lodash_1 = __importDefault(require("lodash"));
class Metadata {
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
    async aliasGet(alias) {
        const relayer = lodash_1.default.sample(await (0, service_options_js_1.getServiceDwnEndpoints)());
        const response = await fetch(`${relayer}/did/${alias}`, {
            method: 'GET',
            mode: 'cors',
            cache: 'no-cache',
            headers: {
                'Accept': '*/*',
                'Content-Type': 'application/json',
            },
        });
        return await response.text();
    }
    async aliasSet(alias, did, metadata = { VerifiableCredentials: [] }) {
        const relayer = lodash_1.default.sample(await (0, service_options_js_1.getServiceDwnEndpoints)());
        const response = await fetch(`${relayer}/did`, {
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
        return await response.text();
    }
    async aliasPut(alias, did, metadata = { VerifiableCredentials: [] }) {
        const relayer = lodash_1.default.sample(await (0, service_options_js_1.getServiceDwnEndpoints)());
        const response = await fetch(`${relayer}/did`, {
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
        return await response.text();
    }
    async save(data) {
        try {
            const b = Buffer.from(data);
            const d = bs58_1.default.encode(b);
            this._ipfs = new ipfs_infura_1.default(await this.config());
            const cid = await this._ipfs.add(d);
            this._ipfs = undefined;
            return this.getBytes32FromIpfsHash(cid.toString());
        }
        catch (e) {
            throw new Error('Failure to submit file to IPFS');
        }
    }
    async get(id) {
        try {
            const cid = this.getIpfsHashFromBytes32(id);
            const response = await fetch(`https://dwn.infura-ipfs.io/ipfs/${multiformats_1.CID.parse(cid).toV1().toString()}`);
            const text = await response.text();
            return bs58_1.default.decode(text).toString();
        }
        catch (e) {
            throw new Error('Failure to get file from IPFS');
        }
    }
    async saveJson(jsonData) {
        try {
            this._ipfs = new ipfs_infura_1.default(await this.config());
            const cid = await this._ipfs.addJSON(jsonData);
            this._ipfs = undefined;
            return this.getBytes32FromIpfsHash(cid.toString());
        }
        catch (e) {
            throw new Error('Failure to submit file to IPFS');
        }
    }
    async getJson(id) {
        try {
            const cid = this.getIpfsHashFromBytes32(id);
            const response = await fetch(`https://dwn.infura-ipfs.io/ipfs/${multiformats_1.CID.parse(cid).toV1().toString()}`);
            const json = await response.json();
            return json;
        }
        catch (e) {
            throw new Error('Failure to get file from IPFS');
        }
    }
    async encrypt(publicKey, input) {
        let encryptionOutput = await id_1.Encryption.eciesSecp256k1Encrypt(publicKey, input);
        return Buffer.from(id_1.Encoder.bytesToString(id_1.Encoder.objectToBytes(encryptionOutput))).toString('base64');
    }
    async decrypt(privateKey, output) {
        let newOutput = {};
        let json = Buffer.from(output, 'base64').toString('ascii');
        Object.entries(JSON.parse(json)).forEach((entry) => {
            const [key, value] = entry;
            //@ts-ignore
            newOutput[key] = value.type == 'Buffer' ? Buffer.from(value.data) : value;
        });
        const decryptionInput = Object.assign({ privateKey }, newOutput);
        //@ts-ignore
        const decryptedPlaintext = await id_1.Encryption.eciesSecp256k1Decrypt(decryptionInput);
        return new TextDecoder().decode(decryptedPlaintext);
    }
    getBytes32FromIpfsHash(ipfsHash) {
        return ('0x' + bs58_1.default.decode(ipfsHash).slice(2).toString('hex'));
    }
    getIpfsHashFromBytes32(bytes32Hex) {
        const hashHex = '1220' + bytes32Hex.slice(2);
        const hashBytes = Buffer.from(hashHex, 'hex');
        const hashStr = bs58_1.default.encode(hashBytes);
        return hashStr;
    }
}
exports.Metadata = Metadata;
//# sourceMappingURL=metadata.js.map