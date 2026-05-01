"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createJwt = exports.decodeJwt = exports.validatePayload = exports.VerifiableCredential = exports.VC_DATA_FORMAT = exports.DEFAULT_VC_TYPE = exports.DEFAULT_CONTEXT = void 0;
const uuid_1 = require("uuid");
const utils_js_1 = require("./utils.js");
const index_js_1 = require("../common/index.js");
const did_jwt_1 = require("did-jwt");
const index_js_2 = require("../dids/index.js");
const validators_js_1 = require("./validators.js");
exports.DEFAULT_CONTEXT = 'https://www.w3.org/2018/credentials/v1';
exports.DEFAULT_VC_TYPE = 'VerifiableCredential';
exports.VC_DATA_FORMAT = 'application/vc+jwt';
const didResolver = new index_js_2.DidResolver({ didResolvers: [index_js_2.DidIonMethod, index_js_2.DidKeyMethod, index_js_2.DidDhtMethod] });
class DwnResolver {
    async resolve(didUrl) {
        return await didResolver.resolve(didUrl); // DIDResolutionResult
    }
}
const dwnResolver = new DwnResolver();
/**
 * `VerifiableCredential` represents a digital verifiable credential according to the
 * [W3C Verifiable Credentials Data Model](https://www.w3.org/TR/vc-data-model/).
 *
 * It provides functionalities to sign, verify, and create credentials, offering a concise API to
 * work with JWT representations of verifiable credentials and ensuring that the signatures
 * and claims within those JWTs can be validated.
 *
 * @property vcDataModel The [VcDataModel] instance representing the core data model of a verifiable credential.
 */
class VerifiableCredential {
    constructor(vcDataModel) {
        this.vcDataModel = vcDataModel;
    }
    get type() {
        return this.vcDataModel.type[this.vcDataModel.type.length - 1];
    }
    get issuer() {
        return this.vcDataModel.issuer.toString();
    }
    get subject() {
        if (Array.isArray(this.vcDataModel.credentialSubject)) {
            return this.vcDataModel.credentialSubject[0].id;
        }
        else {
            return this.vcDataModel.credentialSubject.id;
        }
    }
    /**
     * Sign a verifiable credential using [signOptions]
     *
     *
     * @param signOptions The sign options used to sign the credential.
     * @return The JWT representing the signed verifiable credential.
     *
     * Example:
     * ```
     * const signedVc = verifiableCredential.sign(signOptions)
     * ```
     */
    // TODO: Refactor to look like: sign(did: Did, assertionMethodId?: string)
    async sign(signOptions) {
        const vcJwt = await createJwt({ vc: this.vcDataModel }, signOptions);
        return vcJwt;
    }
    /**
     * Converts the current object to its JSON representation.
     *
     * @return The JSON representation of the object.
     */
    toString() {
        return JSON.stringify(this.vcDataModel);
    }
    /**
     * Create a [VerifiableCredential] based on the provided parameters.
     *
     * @param vcCreateOptions The options to use when creating the Verifiable Credential.
     * @return A [VerifiableCredential] instance.
     *
     * Example:
     * ```
     * const vc = VerifiableCredential.create({
     *     issuer: 'did:ex:issuer',
     *     subject: 'did:ex:subject',
     *     data: { 'arbitrary': 'data' }
     *     type: 'ChiaCredential',
     *   })
     * ```
     */
    static create(vcCreateOptions) {
        const { type, issuer, subject, data, issuanceDate, expirationDate, revocable, suspendable, statusListCredentialId } = vcCreateOptions;
        const jsonData = JSON.parse(JSON.stringify(data));
        if (typeof jsonData !== 'object') {
            throw new Error('Expected data to be parseable into a JSON object');
        }
        if (!issuer || !subject) {
            throw new Error('Issuer and subject must be defined');
        }
        const credentialSubject = Object.assign({ id: subject }, jsonData);
        const vcDataModel = Object.assign({ '@context': [exports.DEFAULT_CONTEXT], type: Array.isArray(type)
                ? [exports.DEFAULT_VC_TYPE, ...type]
                : (type ? [exports.DEFAULT_VC_TYPE, type] : [exports.DEFAULT_VC_TYPE]), id: `urn:uuid:${(0, uuid_1.v4)()}`, issuer: issuer, issuanceDate: issuanceDate || (0, utils_js_1.getCurrentXmlSchema112Timestamp)(), credentialSubject: credentialSubject }, (expirationDate && { expirationDate }));
        // Note: credentialStatus is added by StatusListManager.addCredentialStatus()
        // This is handled at a higher level when creating revocable credentials
        // The revocable/suspendable flags are stored here for reference but
        // actual credentialStatus linking happens via VcApi.createRevocableCredential()
        validatePayload(vcDataModel);
        return new VerifiableCredential(vcDataModel);
    }
    /**
       * Verifies the integrity and authenticity of a Verifiable Credential (VC) encoded as a JSON Web Token (JWT).
       *
       * This function performs several crucial validation steps to ensure the trustworthiness of the provided VC:
       * - Parses and validates the structure of the JWT.
       * - Ensures the presence of critical header elements `alg` and `kid` in the JWT header.
       * - Resolves the Decentralized Identifier (DID) and retrieves the associated DID Document.
       * - Validates the DID and establishes a set of valid verification method IDs.
       * - Identifies the correct Verification Method from the DID Document based on the `kid` parameter.
       * - Verifies the JWT's signature using the public key associated with the Verification Method.
       *
       * If any of these steps fail, the function will throw a [Error] with a message indicating the nature of the failure.
       *
       * @param vcJwt The Verifiable Credential in JWT format as a [string].
       * @throws Error if the verification fails at any step, providing a message with failure details.
       * @throws Error if critical JWT header elements are absent.
       *
       * ### Example:
       * ```
       * try {
       *     VerifiableCredential.verify(signedVcJwt)
       *     console.log("VC Verification successful!")
       * } catch (e: Error) {
       *     console.log("VC Verification failed: ${e.message}")
       * }
       * ```
       */
    static async verify(vcJwt) {
        const jwt = decodeJwt(vcJwt); // Parse and validate JWT
        // Ensure the presence of critical header elements `alg` and `kid`
        if (!jwt.header.alg || !jwt.header.kid) {
            throw new Error('Signature verification failed: Expected JWS header to contain alg and kid');
        }
        const verificationResponse = await (0, did_jwt_1.verifyJWT)(vcJwt, {
            resolver: dwnResolver
        });
        if (!verificationResponse.verified) {
            throw new Error('VC JWT could not be verified. Reason: ' + JSON.stringify(verificationResponse));
        }
    }
    /**
     * Parses a JWT into a [VerifiableCredential] instance.
     *
     * @param vcJwt The verifiable credential JWT as a [String].
     * @return A [VerifiableCredential] instance derived from the JWT.
     *
     * Example:
     * ```
     * val vc = VerifiableCredential.parseJwt(signedVcJwt)
     * ```
     */
    static parseJwt(vcJwt) {
        const decodedVcJwt = decodeJwt(vcJwt);
        const vcDataModel = decodedVcJwt.payload.vc;
        if (!vcDataModel) {
            throw Error('Jwt payload missing vc property');
        }
        return new VerifiableCredential(vcDataModel);
    }
}
exports.VerifiableCredential = VerifiableCredential;
/**
 * Validates the structure and integrity of a Verifiable Credential payload.
 *
 * @param vc - The Verifiable Credential object to validate.
 * @throws Error if any validation check fails.
 */
function validatePayload(vc) {
    validators_js_1.VcValidator.validateContext(vc['@context']);
    validators_js_1.VcValidator.validateVcType(vc.type);
    validators_js_1.VcValidator.validateCredentialSubject(vc.credentialSubject);
    if (vc.issuanceDate)
        validators_js_1.VcValidator.validateTimestamp(vc.issuanceDate);
    if (vc.expirationDate)
        validators_js_1.VcValidator.validateTimestamp(vc.expirationDate);
}
exports.validatePayload = validatePayload;
/**
 * Decodes a VC JWT into its constituent parts: header, payload, and signature.
 *
 * @param jwt - The JWT string to decode.
 * @returns An object containing the decoded header, payload, and signature.
 */
function decodeJwt(jwt) {
    const [encodedHeader, encodedPayload, encodedSignature] = jwt.split('.');
    if (!encodedHeader || !encodedPayload || !encodedSignature) {
        throw Error('Not a valid jwt');
    }
    return {
        header: index_js_1.Convert.base64Url(encodedHeader).toObject(),
        payload: index_js_1.Convert.base64Url(encodedPayload).toObject(),
        signature: encodedSignature
    };
}
exports.decodeJwt = decodeJwt;
/**
 * Create a VC JWT.
 *
 * @param payload - the payload for the JWT.
 * @param signOptions The sign options used to sign the credential.
 * @return The JWT representing the signed verifiable credential.
 */
async function createJwt(payload, signOptions) {
    const { issuerDid, subjectDid, signer, kid } = signOptions;
    const header = { alg: 'EdDSA', typ: 'JWT', kid: kid };
    const jwtPayload = Object.assign({ iss: issuerDid, sub: subjectDid }, payload);
    const encodedHeader = index_js_1.Convert.object(header).toBase64Url();
    const encodedPayload = index_js_1.Convert.object(jwtPayload).toBase64Url();
    const message = encodedHeader + '.' + encodedPayload;
    const messageBytes = index_js_1.Convert.string(message).toUint8Array();
    const signature = await signer(messageBytes);
    const encodedSignature = index_js_1.Convert.uint8Array(signature).toBase64Url();
    const jwt = message + '.' + encodedSignature;
    return jwt;
}
exports.createJwt = createJwt;
//# sourceMappingURL=credential.js.map