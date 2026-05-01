"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.DidDhtMethod = void 0;
const dht_js_1 = require("./dht.js");
const index_js_1 = require("../crypto/index.js");
const utils_js_1 = require("./utils.js");
// for base32
const z32_1 = __importDefault(require("z32"));
const SupportedCryptoKeyTypes = [
    'Ed25519',
    'secp256k1'
];
class DidDhtMethod {
    /**
     * Creates a new DID Document according to the did:dht spec.
     * @param options The options to use when creating the DID Document, including whether to publish it.
     * @returns A promise that resolves to a PortableDid object.
     */
    static async create(options) {
        const { publish = false, relay, keySet: initialKeySet, services } = options !== null && options !== void 0 ? options : {};
        // Generate missing keys, if not provided in the options.
        const keySet = await this.generateKeySet({ keySet: initialKeySet });
        // Get the identifier and set it.
        const identityKey = keySet.verificationMethodKeys.find(key => key.publicKeyJwk.kid === '0');
        const id = await this.getDidIdentifier({ key: identityKey.publicKeyJwk });
        // Add all other keys to the verificationMethod and relationship arrays.
        const relationshipsMap = {};
        const verificationMethods = keySet.verificationMethodKeys.map(key => {
            for (const relationship of key.relationships) {
                if (relationshipsMap[relationship]) {
                    relationshipsMap[relationship].push(`#${key.publicKeyJwk.kid}`);
                }
                else {
                    relationshipsMap[relationship] = [`#${key.publicKeyJwk.kid}`];
                }
            }
            return {
                id: `${id}#${key.publicKeyJwk.kid}`,
                type: 'JsonWebKey2020',
                controller: id,
                // Keep DID document JWK minimal and schema-safe for DWN validators.
                publicKeyJwk: DidDhtMethod.toDidDocumentPublicJwk(key.publicKeyJwk)
            };
        });
        // Normalize service IDs to absolute DID URL form (e.g., did:dht:...#dwn).
        services === null || services === void 0 ? void 0 : services.map(service => {
            if (service.id.startsWith('did:')) {
                return;
            }
            if (service.id.startsWith('#')) {
                service.id = `${id}${service.id}`;
            }
            else {
                service.id = `${id}#${service.id}`;
            }
        });
        // Assemble the DID Document.
        const document = Object.assign(Object.assign({ id, verificationMethod: [...verificationMethods] }, relationshipsMap), services && { service: services });
        // If the publish flag is set, publish the DID Document to the DHT.
        if (publish) {
            await this.publish({ identityKey, didDocument: document, relay });
        }
        return {
            did: document.id,
            document: document,
            keySet: keySet
        };
    }
    /**
     * Generates a JWK key pair.
     * @param options The key algorithm and key ID to use.
     * @returns A promise that resolves to a JwkKeyPair object.
     */
    static async generateJwkKeyPair(options) {
        const { keyAlgorithm, keyId } = options;
        let cryptoKeyPair;
        switch (keyAlgorithm) {
            case 'Ed25519': {
                cryptoKeyPair = await new index_js_1.EdDsaAlgorithm().generateKey({
                    algorithm: { name: 'EdDSA', namedCurve: 'Ed25519' },
                    extractable: true,
                    keyUsages: ['sign', 'verify']
                });
                break;
            }
            case 'secp256k1': {
                cryptoKeyPair = await new index_js_1.EcdsaAlgorithm().generateKey({
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
        const jwkKeyPair = await index_js_1.Jose.cryptoKeyToJwkPair({ keyPair: cryptoKeyPair });
        // Set kid values.
        if (keyId) {
            jwkKeyPair.privateKeyJwk.kid = keyId;
            jwkKeyPair.publicKeyJwk.kid = keyId;
        }
        else {
            // If a key ID is not specified, generate RFC 7638 JWK thumbprint.
            const jwkThumbprint = await index_js_1.Jose.jwkThumbprint({ key: jwkKeyPair.publicKeyJwk });
            jwkKeyPair.privateKeyJwk.kid = jwkThumbprint;
            jwkKeyPair.publicKeyJwk.kid = jwkThumbprint;
        }
        return jwkKeyPair;
    }
    /**
     * Generates a key set for a DID Document.
     * @param options The key set to use when generating the key set.
     * @returns A promise that resolves to a DidDhtKeySet object.
     */
    static async generateKeySet(options) {
        var _a, _b;
        var _c, _d;
        let { keySet = {} } = options !== null && options !== void 0 ? options : {};
        // If the key set is missing a `verificationMethodKeys` array, create one.
        if (!keySet.verificationMethodKeys)
            keySet.verificationMethodKeys = [];
        // If the key set lacks an identity key (`kid: 0`), generate one.
        if (!keySet.verificationMethodKeys.some(key => key.publicKeyJwk.kid === '0')) {
            const identityKey = await this.generateJwkKeyPair({
                keyAlgorithm: 'Ed25519',
                keyId: '0'
            });
            keySet.verificationMethodKeys.push(Object.assign(Object.assign({}, identityKey), { relationships: ['authentication', 'assertionMethod', 'capabilityInvocation', 'capabilityDelegation'] }));
        }
        // Generate RFC 7638 JWK thumbprints if `kid` is missing from any key.
        for (const key of keySet.verificationMethodKeys) {
            if (key.publicKeyJwk)
                (_a = (_c = key.publicKeyJwk).kid) !== null && _a !== void 0 ? _a : (_c.kid = await index_js_1.Jose.jwkThumbprint({ key: key.publicKeyJwk }));
            if (key.privateKeyJwk)
                (_b = (_d = key.privateKeyJwk).kid) !== null && _b !== void 0 ? _b : (_d.kid = await index_js_1.Jose.jwkThumbprint({ key: key.privateKeyJwk }));
        }
        return keySet;
    }
    /**
     * Gets the identifier fragment from a DID.
     * @param options The key to get the identifier fragment from.
     * @returns A promise that resolves to a string containing the identifier.
     */
    static async getDidIdentifier(options) {
        const { key } = options;
        const cryptoKey = await index_js_1.Jose.jwkToCryptoKey({ key });
        const identifier = z32_1.default.encode(cryptoKey.material);
        return 'did:dht:' + identifier;
    }
    /**
     * Gets the identifier fragment from a DID.
     * @param options The key to get the identifier fragment from.
     * @returns A promise that resolves to a string containing the identifier fragment.
     */
    static async getDidIdentifierFragment(options) {
        const { key } = options;
        const cryptoKey = await index_js_1.Jose.jwkToCryptoKey({ key });
        return z32_1.default.encode(cryptoKey.material);
    }
    /**
     * Publishes a DID Document to the DHT.
     * @param keySet The key set to use to sign the DHT payload.
     * @param didDocument The DID Document to publish.
     * @returns A boolean indicating the success of the publishing operation.
     */
    static async publish({ didDocument, identityKey, relay }) {
        const publicCryptoKey = await index_js_1.Jose.jwkToCryptoKey({ key: identityKey.publicKeyJwk });
        const privateCryptoKey = await index_js_1.Jose.jwkToCryptoKey({ key: identityKey.privateKeyJwk });
        const isPublished = await dht_js_1.DidDht.publishDidDocument({
            keyPair: {
                publicKey: publicCryptoKey,
                privateKey: privateCryptoKey
            },
            didDocument,
            relay
        });
        return isPublished;
    }
    /**
     * Resolves a DID Document based on the specified options.
     *
     * @param options - Configuration for resolving a DID Document.
     * @param options.didUrl - The DID URL to resolve.
     * @param options.resolutionOptions - Optional settings for the DID resolution process as defined in the DID Core specification.
     * @returns A Promise that resolves to a `DidResolutionResult`, containing the resolved DID Document and associated metadata.
     */
    static async resolve(options) {
        const { didUrl, resolutionOptions } = options;
        // TODO: Implement resolutionOptions as defined in https://www.w3.org/TR/did-core/#did-resolution
        const parsedDid = (0, utils_js_1.parseDid)({ didUrl });
        if (!parsedDid) {
            return {
                '@context': 'https://w3id.org/did-resolution/v1',
                didDocument: null,
                didDocumentMetadata: {},
                didResolutionMetadata: {
                    contentType: 'application/did+json',
                    error: 'invalidDid',
                    errorMessage: `Cannot parse DID: ${didUrl}`
                }
            };
        }
        if (parsedDid.method !== 'dht') {
            return {
                '@context': 'https://w3id.org/did-resolution/v1',
                didDocument: null,
                didDocumentMetadata: {},
                didResolutionMetadata: {
                    contentType: 'application/did+json',
                    error: 'methodNotSupported',
                    errorMessage: `Method not supported: ${parsedDid.method}`
                }
            };
        }
        let didDocument;
        /**
         * As of 5 Dec 2023, the `pkarr` library throws an error if the DID is not found. Until a
         * better solution is found, catch the error and return a DID Resolution Result with an
         * error message.
         */
        try {
            const relay = resolutionOptions === null || resolutionOptions === void 0 ? void 0 : resolutionOptions.relay;
            didDocument = await dht_js_1.DidDht.getDidDocument({ did: parsedDid.did, relay });
        }
        catch (error) {
            return {
                '@context': 'https://w3id.org/did-resolution/v1',
                didDocument: null,
                didDocumentMetadata: {},
                didResolutionMetadata: {
                    contentType: 'application/did+json',
                    error: 'internalError',
                    errorMessage: `An unexpected error occurred while resolving DID: ${parsedDid.did}`
                }
            };
        }
        return {
            '@context': 'https://w3id.org/did-resolution/v1',
            didDocument,
            didDocumentMetadata: {},
            didResolutionMetadata: {
                contentType: 'application/did+json',
                did: {
                    didString: parsedDid.did,
                    methodSpecificId: parsedDid.id,
                    method: parsedDid.method
                }
            }
        };
    }
    static async getDefaultSigningKey(options) {
        const { didDocument } = options;
        if (didDocument.authentication
            && Array.isArray(didDocument.authentication)
            && didDocument.authentication.length > 0
            && typeof didDocument.authentication[0] === 'string') {
            const [verificationMethodId] = didDocument.authentication;
            const did = didDocument.id;
            const signingKeyId = verificationMethodId.startsWith('#')
                ? `${did}${verificationMethodId}`
                : verificationMethodId;
            return signingKeyId;
        }
    }
    /**
     * Generates a key set and service configuration for a DWN-enabled DID.
     *
     * @param options - Configuration options for generating DWN options
     * @param options.serviceEndpointNodes - Array of DWN endpoint URLs
     * @param options.serviceId - Service ID for the DWN service (defaults to '#dwn')
     * @param options.signingKeyAlgorithm - Algorithm for signing key (defaults to 'Ed25519')
     * @param options.signingKeyId - Key ID for signing key (defaults to '0')
     * @param options.encryptionKeyId - Key ID for encryption key (defaults to '1')
     * @returns A promise that resolves to DidDhtCreateOptions
     */
    static async generateDwnOptions(options) {
        const { signingKeyAlgorithm = 'Ed25519', // Generate Ed25519 key pairs, by default.
        serviceId = '#dwn', // Use default ID value, unless overridden.
        signingKeyId = '0', // Use default key ID value for DHT (identity key)
        encryptionKeyId = '1', // Use default key ID value for encryption key
        serviceEndpointNodes } = options;
        const signingKeyPair = await DidDhtMethod.generateJwkKeyPair({
            keyAlgorithm: signingKeyAlgorithm,
            keyId: signingKeyId
        });
        /** Currently, `id` has only implemented support for record
         * encryption using the `ECIES-ES256K` crypto algorithm. Until the
         * DWN SDK supports ECIES with EdDSA, the encryption key pair must
         * use secp256k1. */
        const encryptionKeyPair = await DidDhtMethod.generateJwkKeyPair({
            keyAlgorithm: 'secp256k1',
            keyId: encryptionKeyId
        });
        const keySet = {
            verificationMethodKeys: [
                Object.assign(Object.assign({}, signingKeyPair), { relationships: ['authentication', 'assertionMethod', 'capabilityInvocation', 'capabilityDelegation'] }),
                Object.assign(Object.assign({}, encryptionKeyPair), { relationships: ['keyAgreement'] })
            ]
        };
        const serviceEndpoint = {
            encryptionKeys: [`#${encryptionKeyId}`],
            nodes: serviceEndpointNodes,
            signingKeys: [`#${signingKeyId}`]
        };
        const services = [{
                id: serviceId,
                serviceEndpoint,
                type: 'DecentralizedWebNode',
            }];
        return { keySet, services };
    }
    /**
     * Convert a JWK to a DID-document-safe public JWK shape.
     * Excludes private and WebCrypto-only properties that can fail downstream
     * schema validation in some DWN implementations.
     */
    static toDidDocumentPublicJwk(publicJwk) {
        const sanitized = {
            alg: publicJwk.alg,
            crv: publicJwk.crv,
            kid: publicJwk.kid,
            kty: publicJwk.kty,
            x: publicJwk.x,
            y: publicJwk.y,
        };
        // Remove undefined fields and any private key material if present.
        delete sanitized.d;
        Object.keys(sanitized).forEach((key) => {
            if (sanitized[key] === undefined)
                delete sanitized[key];
        });
        return sanitized;
    }
}
exports.DidDhtMethod = DidDhtMethod;
DidDhtMethod.methodName = 'dht';
//# sourceMappingURL=did-dht.js.map