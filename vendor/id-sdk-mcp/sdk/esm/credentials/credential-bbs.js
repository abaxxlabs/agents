var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { v4 as uuidv4 } from 'uuid';
import { Bbs } from '../crypto/crypto-primitives/bbs.js';
import { Convert } from '../common/index.js';
import { DidDhtMethod, DidIonMethod, DidKeyMethod, DidResolver } from '../dids/index.js';
import { VcValidator } from './validators.js';
import { getCurrentXmlSchema112Timestamp } from './utils.js';
import { DEFAULT_CONTEXT, DEFAULT_VC_TYPE } from './credential.js';
const didResolver = new DidResolver({ didResolvers: [DidIonMethod, DidKeyMethod, DidDhtMethod] });
export const VC_DATA_FORMAT_LDP = 'application/vc+ld+json';
const ENCODER = new TextEncoder();
/**
 * Converts a credential subject's attributes into an ordered array of
 * messages suitable for BBS+ multi-message signing.
 * The `id` field (subject DID) is always the first message.
 */
function credentialSubjectToMessages(credentialSubject) {
    const keys = [];
    const messages = [];
    const sortedEntries = Object.entries(credentialSubject).sort(([a], [b]) => {
        if (a === 'id')
            return -1;
        if (b === 'id')
            return 1;
        return a.localeCompare(b);
    });
    for (const [key, value] of sortedEntries) {
        keys.push(key);
        const messageStr = typeof value === 'string' ? value : JSON.stringify(value);
        messages.push(ENCODER.encode(`${key}=${messageStr}`));
    }
    return { messages, keys };
}
/**
 * `BbsCredential` provides methods for creating, signing, and deriving
 * selective disclosure proofs from Verifiable Credentials using BBS+
 * signatures on the BLS12-381 curve.
 *
 * Unlike JWT-based credentials that treat the payload as monolithic,
 * BBS+ signs each credential attribute as a separate message, enabling
 * zero-knowledge proofs that reveal only chosen attributes.
 *
 * Usage flow:
 * 1. Issuer: `create()` -> `sign()` -> store full credential in holder's DWN
 * 2. Holder: `deriveProof()` -> selectively disclose attributes to verifier
 * 3. Verifier: `verifyProof()` -> verify the derived proof
 */
export class BbsCredential {
    /**
     * Creates a VC data model suitable for BBS+ signing.
     */
    static create(options) {
        const { type, issuer, subject, data, issuanceDate, expirationDate } = options;
        const jsonData = JSON.parse(JSON.stringify(data));
        if (typeof jsonData !== 'object') {
            throw new Error('Expected data to be parseable into a JSON object');
        }
        if (!issuer || !subject) {
            throw new Error('Issuer and subject must be defined');
        }
        const credentialSubject = Object.assign({ id: subject }, jsonData);
        const vcDataModel = Object.assign({ '@context': [DEFAULT_CONTEXT, 'https://w3id.org/security/data-integrity/v2'], type: Array.isArray(type)
                ? [DEFAULT_VC_TYPE, ...type]
                : type ? [DEFAULT_VC_TYPE, type] : [DEFAULT_VC_TYPE], id: `urn:uuid:${uuidv4()}`, issuer, issuanceDate: issuanceDate || getCurrentXmlSchema112Timestamp(), credentialSubject }, (expirationDate && { expirationDate }));
        VcValidator.validateContext(vcDataModel['@context']);
        VcValidator.validateVcType(vcDataModel.type);
        VcValidator.validateCredentialSubject(vcDataModel.credentialSubject);
        return vcDataModel;
    }
    /**
     * Signs a VC with BBS+. Each attribute in `credentialSubject` becomes a
     * separate BBS+ message, enabling per-attribute selective disclosure.
     *
     * @returns A bundle containing the signed credential, message key order,
     *          and base64url-encoded signature.
     */
    static sign(vcDataModel, signOptions) {
        return __awaiter(this, void 0, void 0, function* () {
            const { kid, issuerDid, keyPair } = signOptions;
            const subject = vcDataModel.credentialSubject;
            const { messages, keys } = credentialSubjectToMessages(Array.isArray(subject) ? subject[0] : subject);
            const signature = yield Bbs.sign({ keyPair, messages });
            const signatureBase64Url = Convert.uint8Array(signature).toBase64Url();
            const proof = {
                type: 'DataIntegrityProof',
                cryptosuite: 'bbs-2023',
                verificationMethod: `${issuerDid}#${kid}`,
                proofPurpose: 'assertionMethod',
                proofValue: signatureBase64Url,
                created: getCurrentXmlSchema112Timestamp(),
            };
            const signedCredential = Object.assign(Object.assign({}, vcDataModel), { proof });
            return {
                credential: signedCredential,
                messageKeys: keys,
                signature: signatureBase64Url,
            };
        });
    }
    /**
     * Verifies a full BBS+ signed credential (not a derived proof).
     * Reconstructs the message array from `credentialSubject` and verifies
     * the signature against the issuer's public key.
     *
     * @param credential - The BBS+ signed VC.
     * @param issuerPublicKey - The issuer's 96-byte BLS12-381 G2 public key.
     * @returns `true` if the signature is valid.
     */
    static verify(credential, issuerPublicKey) {
        return __awaiter(this, void 0, void 0, function* () {
            const proof = credential.proof;
            if (proof.cryptosuite !== 'bbs-2023') {
                throw new Error(`Unsupported cryptosuite: ${proof.cryptosuite}`);
            }
            const signature = Convert.base64Url(proof.proofValue).toUint8Array();
            const subject = credential.credentialSubject;
            const { messages } = credentialSubjectToMessages(Array.isArray(subject) ? subject[0] : subject);
            return Bbs.verify({
                publicKey: issuerPublicKey,
                signature,
                messages,
            });
        });
    }
    /**
     * Derives a zero-knowledge selective disclosure proof from a BBS+ signed
     * credential. The resulting credential contains only the disclosed
     * attributes and a proof that cryptographically demonstrates the holder
     * possesses a valid signature over the full attribute set.
     *
     * @param bundle - The signed credential bundle from `sign()`.
     * @param options - Specifies which attributes to reveal and a session nonce.
     * @returns The derived credential with only disclosed attributes visible.
     */
    static deriveProof(bundle, options) {
        return __awaiter(this, void 0, void 0, function* () {
            const { issuerPublicKey, revealedAttributes, nonce } = options;
            const { credential, messageKeys, signature: signatureBase64Url } = bundle;
            const subject = credential.credentialSubject;
            const flatSubject = Array.isArray(subject) ? subject[0] : subject;
            const { messages } = credentialSubjectToMessages(flatSubject);
            // The `id` field (subject DID) is always disclosed
            const attributesToReveal = new Set(revealedAttributes);
            attributesToReveal.add('id');
            const revealedIndices = [];
            for (let i = 0; i < messageKeys.length; i++) {
                if (attributesToReveal.has(messageKeys[i])) {
                    revealedIndices.push(i);
                }
            }
            if (revealedIndices.length === 0) {
                throw new Error('At least one attribute must be revealed');
            }
            const signatureBytes = Convert.base64Url(signatureBase64Url).toUint8Array();
            const nonceBytes = ENCODER.encode(nonce);
            const proof = yield Bbs.createProof({
                publicKey: issuerPublicKey,
                signature: signatureBytes,
                messages,
                revealed: revealedIndices,
                nonce: nonceBytes,
            });
            const proofBase64Url = Convert.uint8Array(proof).toBase64Url();
            // Build the disclosed credential subject with only revealed attributes
            const disclosedSubject = {};
            const disclosedKeys = [];
            for (const idx of revealedIndices) {
                const key = messageKeys[idx];
                disclosedSubject[key] = flatSubject[key];
                disclosedKeys.push(key);
            }
            const derivedProof = {
                type: 'DataIntegrityProof',
                cryptosuite: 'bbs-2023',
                verificationMethod: credential.proof.verificationMethod,
                proofPurpose: 'assertionMethod',
                proofValue: proofBase64Url,
                nonce,
                created: getCurrentXmlSchema112Timestamp(),
                disclosedIndices: revealedIndices,
            };
            const derivedCredential = Object.assign(Object.assign({ '@context': credential['@context'], type: credential.type, id: credential.id, issuer: credential.issuer, issuanceDate: credential.issuanceDate, credentialSubject: disclosedSubject }, (credential.expirationDate && { expirationDate: credential.expirationDate })), { proof: derivedProof });
            return {
                credential: derivedCredential,
                disclosedKeys,
                disclosedIndices: revealedIndices,
            };
        });
    }
    /**
     * Verifies a BBS+ selective disclosure proof. Only the disclosed messages
     * are checked against the proof — the verifier does not learn the values
     * of undisclosed attributes.
     *
     * @param credential - The derived credential containing a selective disclosure proof.
     * @param issuerPublicKey - The issuer's 96-byte BLS12-381 G2 public key.
     * @returns `true` if the proof is valid.
     */
    static verifyProof(credential, issuerPublicKey) {
        return __awaiter(this, void 0, void 0, function* () {
            const proof = credential.proof;
            if (proof.cryptosuite !== 'bbs-2023') {
                throw new Error(`Unsupported cryptosuite: ${proof.cryptosuite}`);
            }
            if (!proof.nonce) {
                throw new Error('Derived proof must contain a nonce');
            }
            const proofBytes = Convert.base64Url(proof.proofValue).toUint8Array();
            const nonceBytes = ENCODER.encode(proof.nonce);
            const subject = credential.credentialSubject;
            const flatSubject = Array.isArray(subject) ? subject[0] : subject;
            const { messages } = credentialSubjectToMessages(flatSubject);
            return Bbs.verifyProof({
                publicKey: issuerPublicKey,
                proof: proofBytes,
                messages,
                nonce: nonceBytes,
            });
        });
    }
    /**
     * Resolves an issuer DID and attempts to extract the BBS+ public key
     * from the DID document's verification methods.
     *
     * @param issuerDid - The DID of the credential issuer.
     * @param kid - Optional key ID fragment to match a specific verification method.
     * @returns The BLS12-381 G2 public key as Uint8Array, or null if not found.
     */
    static resolveIssuerPublicKey(issuerDid, kid) {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
            const resolution = yield didResolver.resolve(issuerDid);
            const didDocument = resolution === null || resolution === void 0 ? void 0 : resolution.didDocument;
            if (!(didDocument === null || didDocument === void 0 ? void 0 : didDocument.verificationMethod))
                return null;
            for (const vm of didDocument.verificationMethod) {
                const vmId = ((_a = vm.id) === null || _a === void 0 ? void 0 : _a.includes('#')) ? vm.id.split('#')[1] : vm.id;
                if (kid && vmId !== kid)
                    continue;
                if (vm.type === 'Bls12381G2Key2020' ||
                    vm.type === 'JsonWebKey2020' ||
                    vm.type === 'Multikey') {
                    if (vm.publicKeyMultibase) {
                        // Multibase z-prefix = base58btc
                        if (vm.publicKeyMultibase.startsWith('z')) {
                            return Convert.base58Btc(vm.publicKeyMultibase.slice(1)).toUint8Array();
                        }
                    }
                    if (vm.publicKeyJwk) {
                        const jwk = vm.publicKeyJwk;
                        if (jwk.x) {
                            return Convert.base64Url(jwk.x).toUint8Array();
                        }
                    }
                }
            }
            return null;
        });
    }
}
//# sourceMappingURL=credential-bbs.js.map