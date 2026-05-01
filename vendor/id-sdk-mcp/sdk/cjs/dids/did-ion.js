"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.DidIonMethod = void 0;
const index_js_1 = require("../common/index.js");
const ion_pow_sdk_1 = __importDefault(require("@decentralized-identity/ion-pow-sdk"));
const index_js_2 = require("../crypto/index.js");
const ion_sdk_1 = require("@decentralized-identity/ion-sdk");
const utils_js_1 = require("./utils.js");
var OperationType;
(function (OperationType) {
    OperationType["Create"] = "create";
    OperationType["Update"] = "update";
    OperationType["Deactivate"] = "deactivate";
    OperationType["Recover"] = "recover";
})(OperationType || (OperationType = {}));
const SupportedCryptoAlgorithms = [
    'Ed25519',
    'secp256k1'
];
const VerificationRelationshipToIonPublicKeyPurpose = {
    assertionMethod: ion_sdk_1.IonPublicKeyPurpose.AssertionMethod,
    authentication: ion_sdk_1.IonPublicKeyPurpose.Authentication,
    capabilityDelegation: ion_sdk_1.IonPublicKeyPurpose.CapabilityDelegation,
    capabilityInvocation: ion_sdk_1.IonPublicKeyPurpose.CapabilityInvocation,
    keyAgreement: ion_sdk_1.IonPublicKeyPurpose.KeyAgreement
};
class DidIonMethod {
    static async anchor(options) {
        const { challengeEnabled = true, challengeEndpoint = 'https://beta.ion.msidentity.com/api/v1.0/proof-of-work-challenge', keySet, services, operationsEndpoint = 'https://beta.ion.msidentity.com/api/v1.0/operations' } = options;
        // Create ION Document.
        const ionDocument = await DidIonMethod.createIonDocument({
            keySet: keySet,
            services
        });
        const createRequest = await DidIonMethod.getIonCreateRequest({
            ionDocument,
            recoveryPublicKeyJwk: keySet.recoveryKey.publicKeyJwk,
            updatePublicKeyJwk: keySet.updateKey.publicKeyJwk
        });
        let resolutionResult;
        if (challengeEnabled) {
            const response = await ion_pow_sdk_1.default.submitIonRequest(challengeEndpoint, operationsEndpoint, JSON.stringify(createRequest));
            if (response !== undefined && (0, index_js_1.universalTypeOf)(response) === 'String') {
                resolutionResult = JSON.parse(response);
            }
        }
        else {
            const response = await fetch(operationsEndpoint, {
                method: 'POST',
                mode: 'cors',
                body: JSON.stringify(createRequest),
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            if (response.ok) {
                resolutionResult = await response.json();
            }
        }
        return resolutionResult;
    }
    static async create(options) {
        let { anchor, keyAlgorithm, keySet, services } = options !== null && options !== void 0 ? options : {};
        // Begin constructing a PortableDid.
        const did = {};
        // If any member of the key set is missing, generate the keys.
        did.keySet = await DidIonMethod.generateKeySet({ keyAlgorithm, keySet });
        // Generate Long Form DID URI.
        did.did = await DidIonMethod.getLongFormDid({
            keySet: did.keySet,
            services
        });
        // Get short form DID.
        did.canonicalId = await DidIonMethod.getShortFormDid({ didUrl: did.did });
        let didResolutionResult;
        if (anchor) {
            // Attempt to anchor the DID.
            didResolutionResult = await DidIonMethod.anchor({
                keySet: did.keySet,
                services
            });
        }
        else {
            // If anchoring was not requested, then resolve the long form DID.
            didResolutionResult = await DidIonMethod.resolve({ didUrl: did.did });
        }
        // Store the DID Document.
        did.document = didResolutionResult.didDocument;
        return did;
    }
    static async decodeLongFormDid(options) {
        const { didUrl } = options;
        const parsedDid = (0, utils_js_1.parseDid)({ didUrl });
        if (!parsedDid) {
            throw new Error(`DidIonMethod: Unable to parse DID: ${didUrl}`);
        }
        const decodedLongFormDid = index_js_1.Convert.base64Url(parsedDid.id.split(':').pop()).toObject();
        const createRequest = Object.assign(Object.assign({}, decodedLongFormDid), { type: OperationType.Create });
        return createRequest;
    }
    /**
     * Generates two key pairs used for authorization and encryption purposes
     * when interfacing with DWNs. The IDs of these keys are referenced in the
     * service object that includes the dwnUrls provided.
     */
    static async generateDwnOptions(options) {
        const { signingKeyAlgorithm = 'Ed25519', // Generate Ed25519 key pairs, by default.
        serviceId = '#dwn', // Use default ID value, unless overridden.
        signingKeyId = '#dwn-sig', // Use default key ID value, unless overridden.
        encryptionKeyId = '#dwn-enc', // Use default key ID value, unless overridden.
        serviceEndpointNodes } = options;
        const signingKeyPair = await DidIonMethod.generateJwkKeyPair({
            keyAlgorithm: signingKeyAlgorithm,
            keyId: signingKeyId
        });
        /** Currently, `id` has only implemented support for record
         * encryption using the `ECIES-ES256K` crypto algorithm. Until the
         * DWN SDK supports ECIES with EdDSA, the encryption key pair must
         * use secp256k1. */
        const encryptionKeyPair = await DidIonMethod.generateJwkKeyPair({
            keyAlgorithm: 'secp256k1',
            keyId: encryptionKeyId
        });
        const keySet = {
            verificationMethodKeys: [
                Object.assign(Object.assign({}, signingKeyPair), { relationships: ['authentication'] }),
                Object.assign(Object.assign({}, encryptionKeyPair), { relationships: ['keyAgreement'] })
            ]
        };
        const serviceEndpoint = {
            encryptionKeys: [encryptionKeyId],
            nodes: serviceEndpointNodes,
            signingKeys: [signingKeyId]
        };
        const services = [{
                id: serviceId,
                serviceEndpoint,
                type: 'DecentralizedWebNode',
            }];
        return { keySet, services };
    }
    static async generateJwkKeyPair(options) {
        const { keyAlgorithm, keyId } = options;
        let cryptoKeyPair;
        switch (keyAlgorithm) {
            case 'Ed25519': {
                cryptoKeyPair = await new index_js_2.EdDsaAlgorithm().generateKey({
                    algorithm: { name: 'EdDSA', namedCurve: 'Ed25519' },
                    extractable: true,
                    keyUsages: ['sign', 'verify']
                });
                break;
            }
            case 'secp256k1': {
                cryptoKeyPair = await new index_js_2.EcdsaAlgorithm().generateKey({
                    algorithm: { name: 'ECDSA', namedCurve: 'secp256k1' },
                    extractable: true,
                    keyUsages: ['sign', 'verify']
                });
                break;
            }
            default: {
                throw new Error(`Unsupported crypto algorithm: '${keyAlgorithm}'`);
            }
        }
        // Convert the CryptoKeyPair to JwkKeyPair.
        const jwkKeyPair = await index_js_2.Jose.cryptoKeyToJwkPair({ keyPair: cryptoKeyPair });
        // Set kid values.
        if (keyId) {
            jwkKeyPair.privateKeyJwk.kid = keyId;
            jwkKeyPair.publicKeyJwk.kid = keyId;
        }
        else {
            // If a key ID is not specified, generate RFC 7638 JWK thumbprint.
            const jwkThumbprint = await index_js_2.Jose.jwkThumbprint({ key: jwkKeyPair.publicKeyJwk });
            jwkKeyPair.privateKeyJwk.kid = jwkThumbprint;
            jwkKeyPair.publicKeyJwk.kid = jwkThumbprint;
        }
        return jwkKeyPair;
    }
    static async generateKeySet(options) {
        var _a, _b;
        var _c, _d;
        // Generate Ed25519 authentication key pair, by default.
        let { keyAlgorithm = 'Ed25519', keySet = {} } = options !== null && options !== void 0 ? options : {};
        // If keySet lacks verification method keys, generate one.
        if (keySet.verificationMethodKeys === undefined) {
            const authenticationkeyPair = await DidIonMethod.generateJwkKeyPair({
                keyAlgorithm,
                keyId: 'dwn-sig'
            });
            keySet.verificationMethodKeys = [Object.assign(Object.assign({}, authenticationkeyPair), { relationships: ['authentication', 'assertionMethod'] })];
        }
        // If keySet lacks recovery key, generate one.
        if (keySet.recoveryKey === undefined) {
            // Note: ION/Sidetree only supports secp256k1 recovery keys.
            keySet.recoveryKey = await DidIonMethod.generateJwkKeyPair({
                keyAlgorithm: 'secp256k1',
                keyId: 'ion-recovery-1'
            });
        }
        // If keySet lacks update key, generate one.
        if (keySet.updateKey === undefined) {
            // Note: ION/Sidetree only supports secp256k1 update keys.
            keySet.updateKey = await DidIonMethod.generateJwkKeyPair({
                keyAlgorithm: 'secp256k1',
                keyId: 'ion-update-1'
            });
        }
        // Generate RFC 7638 JWK thumbprints if `kid` is missing from any key.
        for (const key of [...keySet.verificationMethodKeys, keySet.recoveryKey, keySet.updateKey]) {
            if ('publicKeyJwk' in key)
                (_a = (_c = key.publicKeyJwk).kid) !== null && _a !== void 0 ? _a : (_c.kid = await index_js_2.Jose.jwkThumbprint({ key: key.publicKeyJwk }));
            if ('privateKeyJwk' in key)
                (_b = (_d = key.privateKeyJwk).kid) !== null && _b !== void 0 ? _b : (_d.kid = await index_js_2.Jose.jwkThumbprint({ key: key.privateKeyJwk }));
        }
        return keySet;
    }
    /**
     * Given the W3C DID Document of a `did:ion` DID, return the identifier of
     * the verification method key that will be used for signing messages and
     * credentials, by default.
     *
     * @param document = DID Document to get the default signing key from.
     * @returns Verification method identifier for the default signing key.
     */
    static async getDefaultSigningKey(options) {
        const { didDocument } = options;
        if (!didDocument.id) {
            throw new Error(`DidIonMethod: DID document is missing 'id' property`);
        }
        /** If the DID document contains a DWN service endpoint in the expected
         * format, return the first entry in the `signingKeys` array. */
        const [dwnService] = (0, utils_js_1.getServices)({ didDocument, type: 'DecentralizedWebNode' });
        if ((0, utils_js_1.isDwnServiceEndpoint)(dwnService === null || dwnService === void 0 ? void 0 : dwnService.serviceEndpoint)) {
            const [verificationMethodId] = dwnService.serviceEndpoint.signingKeys;
            const did = didDocument.id;
            const signingKeyId = `${did}${verificationMethodId}`;
            return signingKeyId;
        }
        /** Otherwise, fallback to a naive approach of returning the first key ID
         * in the `authentication` verification relationships array. */
        if (didDocument.authentication
            && Array.isArray(didDocument.authentication)
            && didDocument.authentication.length > 0
            && typeof didDocument.authentication[0] === 'string') {
            const [verificationMethodId] = didDocument.authentication;
            const did = didDocument.id;
            const signingKeyId = `${did}${verificationMethodId}`;
            return signingKeyId;
        }
    }
    static async getLongFormDid(options) {
        const { services = [], keySet } = options;
        // Create ION Document.
        const ionDocument = await DidIonMethod.createIonDocument({
            keySet: keySet,
            services
        });
        // Filter JWK to only those properties expected by ION/Sidetree.
        const recoveryKey = DidIonMethod.jwkToIonJwk({ key: keySet.recoveryKey.publicKeyJwk });
        const updateKey = DidIonMethod.jwkToIonJwk({ key: keySet.updateKey.publicKeyJwk });
        // Create an ION DID create request operation.
        const did = await ion_sdk_1.IonDid.createLongFormDid({
            document: ionDocument,
            recoveryKey,
            updateKey
        });
        return did;
    }
    static async getShortFormDid(options) {
        const { didUrl } = options;
        const parsedDid = (0, utils_js_1.parseDid)({ didUrl });
        if (!parsedDid) {
            throw new Error(`DidIonMethod: Unable to parse DID: ${didUrl}`);
        }
        const shortFormDid = parsedDid.did.split(':', 3).join(':');
        return shortFormDid;
    }
    static async resolve(options) {
        var _a;
        // TODO: add resolutionOptions as defined in https://www.w3.org/TR/did-core/#did-resolution
        const { didUrl, resolutionOptions = {} } = options;
        const parsedDid = (0, utils_js_1.parseDid)({ didUrl });
        if (!parsedDid) {
            return {
                '@context': 'https://w3id.org/did-resolution/v1',
                didDocument: undefined,
                didDocumentMetadata: {},
                didResolutionMetadata: {
                    contentType: 'application/did+json',
                    error: 'invalidDid',
                    errorMessage: `Cannot parse DID: ${didUrl}`
                }
            };
        }
        if (parsedDid.method !== 'ion') {
            return {
                '@context': 'https://w3id.org/did-resolution/v1',
                didDocument: undefined,
                didDocumentMetadata: {},
                didResolutionMetadata: {
                    contentType: 'application/did+json',
                    error: 'methodNotSupported',
                    errorMessage: `Method not supported: ${parsedDid.method}`
                }
            };
        }
        const { resolutionEndpoint = 'https://discover.did.msidentity.com/1.0/identifiers/' } = resolutionOptions;
        const normalizeUrl = (url) => url.endsWith('/') ? url : url + '/';
        const resolutionUrl = `${normalizeUrl(resolutionEndpoint)}${parsedDid.did}`;
        const response = await fetch(resolutionUrl);
        let resolutionResult;
        try {
            resolutionResult = await response.json();
        }
        catch (error) {
            resolutionResult = {};
        }
        if (response.ok) {
            return resolutionResult;
        }
        // Response was not "OK" (HTTP 4xx-5xx status code)
        // Return result if it contains DID resolution metadata.
        if ('didResolutionMetadata' in resolutionResult) {
            return resolutionResult;
        }
        // Set default error code and message.
        let error = 'internalError';
        let errorMessage = `DID resolver responded with HTTP status code: ${response.status}`;
        /** The Microsoft resolution endpoint does not return a valid DidResolutionResult
           * when an ION DID is "not found" so normalization is needed. */
        if ('error' in resolutionResult &&
            typeof resolutionResult.error === 'object' &&
            'code' in resolutionResult.error &&
            typeof resolutionResult.error.code === 'string' &&
            'message' in resolutionResult.error &&
            typeof resolutionResult.error.message === 'string') {
            error = resolutionResult.error.code.includes('not_found') ? 'notFound' : error;
            errorMessage = (_a = resolutionResult.error.message) !== null && _a !== void 0 ? _a : errorMessage;
        }
        return {
            '@context': 'https://w3id.org/did-resolution/v1',
            didDocument: undefined,
            didDocumentMetadata: {},
            didResolutionMetadata: {
                contentType: 'application/did+json',
                error,
                errorMessage
            }
        };
    }
    static async createIonDocument(options) {
        const { services = [], keySet } = options;
        /**
         * STEP 1: Convert key set verification method keys to ION SDK format.
         */
        const ionPublicKeys = [];
        for (const key of keySet.verificationMethodKeys) {
            // Map W3C DID verification relationship names to ION public key purposes.
            const ionPurposes = [];
            for (const relationship of key.relationships) {
                ionPurposes.push(VerificationRelationshipToIonPublicKeyPurpose[relationship]);
            }
            /** During certain ION operations, JWK validation will throw an error
             * if key IDs provided as input are prefixed with `#`. ION operation
             * outputs and DID document resolution always include the `#` prefix
             * for key IDs resulting in a confusing mismatch between inputs and
             * outputs.  To improve the developer experience, this inconsistency
             * is addressed by normalizing input key IDs before being passed
             * to ION SDK methods. */
            const publicKeyId = (key.publicKeyJwk.kid.startsWith('#'))
                ? key.publicKeyJwk.kid.substring(1)
                : key.publicKeyJwk.kid;
            // Convert public key JWK to ION format.
            const publicKey = {
                id: publicKeyId,
                publicKeyJwk: DidIonMethod.jwkToIonJwk({ key: key.publicKeyJwk }),
                purposes: ionPurposes,
                type: 'JsonWebKey2020'
            };
            ionPublicKeys.push(publicKey);
        }
        /**
         * STEP 2: Convert service entries, if any, to ION SDK format.
         */
        const ionServices = services.map(service => (Object.assign(Object.assign({}, service), { id: service.id.startsWith('#') ? service.id.substring(1) : service.id })));
        /**
         * STEP 3: Format as ION document.
         */
        const ionDocumentModel = {
            publicKeys: ionPublicKeys,
            services: ionServices
        };
        return ionDocumentModel;
    }
    static async getIonCreateRequest(options) {
        const { ionDocument, recoveryPublicKeyJwk, updatePublicKeyJwk } = options;
        // Create an ION DID create request operation.
        const createRequest = await ion_sdk_1.IonRequest.createCreateRequest({
            document: ionDocument,
            recoveryKey: DidIonMethod.jwkToIonJwk({ key: recoveryPublicKeyJwk }),
            updateKey: DidIonMethod.jwkToIonJwk({ key: updatePublicKeyJwk })
        });
        return createRequest;
    }
    static jwkToIonJwk({ key }) {
        let ionJwk = {};
        if ('crv' in key) {
            ionJwk.crv = key.crv;
            ionJwk.kty = key.kty;
            ionJwk.x = key.x;
            if ('d' in key)
                ionJwk.d = key.d;
            if ('y' in key && key.y) {
                // secp256k1 JWK.
                return Object.assign(Object.assign({}, ionJwk), { y: key.y });
            }
            // Ed25519 JWK.
            return Object.assign({}, ionJwk);
        }
        throw new Error(`jwkToIonJwk: Unsupported key algorithm.`);
    }
}
exports.DidIonMethod = DidIonMethod;
/**
 * Name of the DID method
*/
DidIonMethod.methodName = 'ion';
//# sourceMappingURL=did-ion.js.map