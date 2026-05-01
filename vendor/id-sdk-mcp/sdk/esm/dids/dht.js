var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { Jose } from '../crypto/index.js';
import { Convert } from '../common/index.js';
import { Pkarr, SignedPacket, z32 } from 'pkarr';
import { AUTHORITATIVE_ANSWER } from 'dns-packet';
import { Buffer } from 'buffer';
const DEFAULT_PKARR_RELAY = 'https://relay.dwn.id/dht';
// const DEFAULT_PKARR_RELAY = 'http://localhost:8305';
const TTL = 7200;
function ensureBufferBigIntMethods() {
    const proto = Buffer === null || Buffer === void 0 ? void 0 : Buffer.prototype;
    if (!proto)
        return;
    if (typeof proto.writeBigUInt64BE !== 'function') {
        proto.writeBigUInt64BE = function writeBigUInt64BE(value, offset = 0) {
            const bigintValue = typeof value === 'bigint' ? value : BigInt(value);
            const view = new DataView(this.buffer, this.byteOffset, this.byteLength);
            view.setBigUint64(offset, bigintValue, false);
            return offset + 8;
        };
    }
    if (typeof proto.readBigUInt64BE !== 'function') {
        proto.readBigUInt64BE = function readBigUInt64BE(offset = 0) {
            const view = new DataView(this.buffer, this.byteOffset, this.byteLength);
            return view.getBigUint64(offset, false);
        };
    }
}
/**
 * A class to handle operations related to DHT-based Decentralized Identifiers (DIDs).
 * It provides methods to:
 * - Parse a DNS packet into a DID Document.
 * - Retrieve a DID Document from the DHT.
 * - Publish a DID Document to the DHT.
 * - Convert a DID Document to a DNS packet.
 *
 * The class assumes that DIDs and DID Documents are compliant with the did:dht specification.
 */
export class DidDht {
    static setRelayUrl(relayUrl) {
        this.relayUrl = relayUrl;
    }
    static getRelayUrl() {
        return this.relayUrl;
    }
    /**
     * Parses a DNS packet into a DID Document.
     * @param did The DID of the document.
     * @param packet A DNS packet to parse into a DID Document.
     * @returns A Promise that resolves to the parsed DidDocument.
     */
    static fromDnsPacket({ did, packet }) {
        var _a, _b, _c;
        return __awaiter(this, void 0, void 0, function* () {
            const document = {
                id: did,
            };
            const keyLookup = new Map();
            for (const answer of packet.answers) {
                if (answer.type !== 'TXT')
                    continue;
                const dataStr = (_a = answer.data) === null || _a === void 0 ? void 0 : _a.toString();
                // Extracts 'k' or 's' from "_k0._did" or "_s0._did"
                const recordType = (_b = answer.name) === null || _b === void 0 ? void 0 : _b.split('.')[0].substring(1, 2);
                /*eslint-disable no-case-declarations*/
                switch (recordType) {
                    case 'k': {
                        const { id, t, k } = DidDht.parseTxtData({ data: dataStr });
                        const keyConfigurations = {
                            '0': {
                                crv: 'Ed25519',
                                kty: 'OKP',
                                alg: 'EdDSA'
                            },
                            '1': {
                                crv: 'secp256k1',
                                kty: 'EC',
                                alg: 'ES256K'
                            }
                        };
                        const keyConfig = keyConfigurations[t];
                        if (!keyConfig) {
                            throw new Error('Unsupported key type');
                        }
                        const publicKeyJwk = yield Jose.keyToJwk(Object.assign(Object.assign({}, keyConfig), { kid: id, keyMaterial: Convert.base64Url(k).toUint8Array(), keyType: 'public' }));
                        if (!document.verificationMethod) {
                            document.verificationMethod = [];
                        }
                        document.verificationMethod.push({
                            id: `${did}#${id}`,
                            type: 'JsonWebKey2020',
                            controller: did,
                            publicKeyJwk: publicKeyJwk,
                        });
                        keyLookup.set(answer.name, id);
                        break;
                    }
                    case 's': {
                        const { id: sId, t: sType, uri } = DidDht.parseTxtData({ data: dataStr });
                        if (!document.service) {
                            document.service = [];
                        }
                        document.service.push({
                            id: `${did}#${sId}`,
                            type: sType,
                            serviceEndpoint: DidDht.decodeServiceEndpoint({ encoded: uri })
                        });
                        break;
                    }
                }
            }
            // Extract relationships from root record
            const didSuffix = did.split('did:dht:')[1];
            const potentialRootNames = ['_did', `_did.${didSuffix}`];
            let actualRootName = null;
            const root = packet.answers
                .filter(answer => {
                if (potentialRootNames.includes(answer.name)) {
                    actualRootName = answer.name;
                    return true;
                }
                return false;
            });
            if (root.length === 0) {
                throw new Error('No root record found');
            }
            if (root.length > 1) {
                throw new Error('Multiple root records found');
            }
            const singleRoot = root[0];
            const rootRecord = (_c = singleRoot.data) === null || _c === void 0 ? void 0 : _c.toString().split(';');
            rootRecord === null || rootRecord === void 0 ? void 0 : rootRecord.forEach(record => {
                const [type, ids] = record.split('=');
                let idList = ids === null || ids === void 0 ? void 0 : ids.split(',').map(id => `#${keyLookup.get(`_${id}.${actualRootName}`)}`);
                switch (type) {
                    case 'auth':
                        document.authentication = idList;
                        break;
                    case 'asm':
                        document.assertionMethod = idList;
                        break;
                    case 'agm':
                        document.keyAgreement = idList;
                        break;
                    case 'inv':
                        document.capabilityInvocation = idList;
                        break;
                    case 'del':
                        document.capabilityDelegation = idList;
                        break;
                }
            });
            return document;
        });
    }
    /**
     * Retrieves a DID Document from the DHT.
     *
     * @param did The DID of the document to retrieve.
     * @param relay The relay to use to retrieve the document; defaults to `PKARR_RELAY`.
     * @returns A Promise that resolves to the retrieved DidDocument.
     */
    static getDidDocument({ did, relay }) {
        return __awaiter(this, void 0, void 0, function* () {
            ensureBufferBigIntMethods();
            const relayUrl = relay !== null && relay !== void 0 ? relay : DidDht.getRelayUrl();
            const didFragment = did.replace('did:dht:', '');
            const publicKeyBytes = new Uint8Array(z32.decode(didFragment));
            const resolved = yield Pkarr.relayGet(relayUrl, publicKeyBytes);
            if (resolved) {
                return yield DidDht.fromDnsPacket({ did, packet: resolved.packet() });
            }
            throw new Error('No packet found');
        });
    }
    /**
     * Publishes a DID Document to the DHT.
     *
     * @param keyPair The key pair to sign the document with.
     * @param didDocument The DID Document to publish.
     * @param relay The relay to use to retrieve the document; defaults to `PKARR_RELAY`.
     * @returns A boolean indicating the success of the publishing operation.
     */
    static publishDidDocument({ keyPair, didDocument, relay }) {
        return __awaiter(this, void 0, void 0, function* () {
            ensureBufferBigIntMethods();
            const relayUrl = relay !== null && relay !== void 0 ? relay : DidDht.getRelayUrl();
            const packet = yield DidDht.toDnsPacket({ didDocument });
            const pkarrKeypair = {
                publicKey: keyPair.publicKey.material,
                secretKey: new Uint8Array([...keyPair.privateKey.material, ...keyPair.publicKey.material])
            };
            const signedPacket = SignedPacket.fromPacket(pkarrKeypair, packet);
            const results = yield Pkarr.relayPut(relayUrl, signedPacket);
            return results.ok;
        });
    }
    /**
     * Converts a DID Document to a DNS packet according to the did:dht spec.
     *
     * @param didDocument The DID Document to convert.
     * @returns A DNS packet converted from the DID Document.
     */
    static toDnsPacket({ didDocument }) {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
            const packet = {
                id: 0,
                type: 'response',
                flags: AUTHORITATIVE_ANSWER,
                answers: []
            };
            const vmIds = [];
            const svcIds = [];
            const rootRecord = [];
            const keyLookup = new Map();
            // Add key records for each verification method
            for (const vm of didDocument.verificationMethod) {
                const index = didDocument.verificationMethod.indexOf(vm);
                const recordIdentifier = `k${index}`;
                let vmId = DidDht.identifierFragment({ identifier: vm.id });
                keyLookup.set(vmId, recordIdentifier);
                let keyType;
                switch (vm.publicKeyJwk.alg) {
                    case 'EdDSA':
                        keyType = 0;
                        break;
                    case 'ES256K':
                        keyType = 1;
                        break;
                    default:
                        keyType = 0; // Default value or throw an error if needed
                }
                // DID document JWKs intentionally omit WebCrypto-only fields such as
                // `ext` and `key_ops`, so decode key bytes directly from JWK.
                const { keyMaterial } = yield Jose.jwkToKey({ key: vm.publicKeyJwk });
                const keyBase64Url = Convert.uint8Array(keyMaterial).toBase64Url();
                const keyRecord = {
                    type: 'TXT',
                    name: `_${recordIdentifier}._did`,
                    ttl: TTL,
                    data: `id=${vmId},t=${keyType},k=${keyBase64Url}`
                };
                packet.answers.push(keyRecord);
                vmIds.push(recordIdentifier);
            }
            // Add service records
            (_a = didDocument.service) === null || _a === void 0 ? void 0 : _a.forEach((service, index) => {
                const recordIdentifier = `s${index}`;
                let sId = DidDht.identifierFragment({ identifier: service.id });
                const encodedServiceEndpoint = DidDht.encodeServiceEndpoint({ serviceEndpoint: service.serviceEndpoint });
                const serviceRecord = {
                    type: 'TXT',
                    name: `_${recordIdentifier}._did`,
                    ttl: TTL,
                    data: `id=${sId},t=${service.type},uri=${encodedServiceEndpoint}`
                };
                packet.answers.push(serviceRecord);
                svcIds.push(recordIdentifier);
            });
            // add root record for vms and svcs
            if (vmIds.length) {
                rootRecord.push(`vm=${vmIds.join(',')}`);
            }
            if (svcIds.length) {
                rootRecord.push(`svc=${svcIds.join(',')}`);
            }
            // add verification relationships
            if (didDocument.authentication) {
                const authIds = didDocument.authentication
                    .map(id => DidDht.identifierFragment({ identifier: id }))
                    .filter(id => keyLookup.has(id))
                    .map(id => keyLookup.get(id));
                if (authIds.length) {
                    rootRecord.push(`auth=${authIds.join(',')}`);
                }
            }
            if (didDocument.assertionMethod) {
                const authIds = didDocument.assertionMethod
                    .map(id => DidDht.identifierFragment({ identifier: id }))
                    .filter(id => keyLookup.has(id))
                    .map(id => keyLookup.get(id));
                if (authIds.length) {
                    rootRecord.push(`asm=${authIds.join(',')}`);
                }
            }
            if (didDocument.keyAgreement) {
                const authIds = didDocument.keyAgreement
                    .map(id => DidDht.identifierFragment({ identifier: id }))
                    .filter(id => keyLookup.has(id))
                    .map(id => keyLookup.get(id));
                if (authIds.length) {
                    rootRecord.push(`agm=${authIds.join(',')}`);
                }
            }
            if (didDocument.capabilityInvocation) {
                const authIds = didDocument.capabilityInvocation
                    .map(id => DidDht.identifierFragment({ identifier: id }))
                    .filter(id => keyLookup.has(id))
                    .map(id => keyLookup.get(id));
                if (authIds.length) {
                    rootRecord.push(`inv=${authIds.join(',')}`);
                }
            }
            if (didDocument.capabilityDelegation) {
                const authIds = didDocument.capabilityDelegation
                    .map(id => DidDht.identifierFragment({ identifier: id }))
                    .filter(id => keyLookup.has(id))
                    .map(id => keyLookup.get(id));
                if (authIds.length) {
                    rootRecord.push(`del=${authIds.join(',')}`);
                }
            }
            // Add root record
            packet.answers.push({
                type: 'TXT',
                name: '_did',
                ttl: TTL,
                data: rootRecord.join(';')
            });
            return packet;
        });
    }
    /**
     * Extracts the fragment from a DID.
     *
     * @param identifier The DID to extract the fragment from.
     * @returns The fragment from the DID or the complete DID if no fragment exists.
     */
    static identifierFragment({ identifier }) {
        return identifier.includes('#') ? identifier.substring(identifier.indexOf('#') + 1) : identifier;
    }
    /**
     * Parses TXT data from a DNS answer to extract key or service information.
     *
     * @param data The TXT record string data containing key-value pairs separated by commas.
     * @returns An object containing parsed attributes such as 'id', 't', 'k', and 'uri'.
    */
    static parseTxtData({ data }) {
        return data.split(',').reduce((acc, pair) => {
            const [key, value] = pair.split('=');
            acc[key] = value;
            return acc;
        }, {});
    }
    static encodeServiceEndpoint({ serviceEndpoint }) {
        return Convert.object({ serviceEndpoint }).toBase64Url();
    }
    static decodeServiceEndpoint({ encoded }) {
        try {
            const decoded = Convert.base64Url(encoded).toObject();
            if (decoded && 'serviceEndpoint' in decoded) {
                return decoded.serviceEndpoint;
            }
        }
        catch (_a) {
            // Backward compatibility for pre-encoded records.
        }
        return encoded;
    }
}
DidDht.relayUrl = DEFAULT_PKARR_RELAY;
//# sourceMappingURL=dht.js.map