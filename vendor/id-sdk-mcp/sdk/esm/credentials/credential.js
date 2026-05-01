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
import { getCurrentXmlSchema112Timestamp } from './utils.js';
import { Convert } from '../common/index.js';
import { verifyJWT } from 'did-jwt';
import { DidDhtMethod, DidIonMethod, DidKeyMethod, DidResolver } from '../dids/index.js';
import { VcValidator } from './validators.js';
export const DEFAULT_CONTEXT = 'https://www.w3.org/2018/credentials/v1';
export const DEFAULT_VC_TYPE = 'VerifiableCredential';
export const VC_DATA_FORMAT = 'application/vc+jwt';
const didResolver = new DidResolver({ didResolvers: [DidIonMethod, DidKeyMethod, DidDhtMethod] });
class DwnResolver {
    resolve(didUrl) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield didResolver.resolve(didUrl); // DIDResolutionResult
        });
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
export class VerifiableCredential {
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
    sign(signOptions) {
        return __awaiter(this, void 0, void 0, function* () {
            const vcJwt = yield createJwt({ vc: this.vcDataModel }, signOptions);
            return vcJwt;
        });
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
        const vcDataModel = Object.assign({ '@context': [DEFAULT_CONTEXT], type: Array.isArray(type)
                ? [DEFAULT_VC_TYPE, ...type]
                : (type ? [DEFAULT_VC_TYPE, type] : [DEFAULT_VC_TYPE]), id: `urn:uuid:${uuidv4()}`, issuer: issuer, issuanceDate: issuanceDate || getCurrentXmlSchema112Timestamp(), credentialSubject: credentialSubject }, (expirationDate && { expirationDate }));
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
    static verify(vcJwt) {
        return __awaiter(this, void 0, void 0, function* () {
            const jwt = decodeJwt(vcJwt); // Parse and validate JWT
            // Ensure the presence of critical header elements `alg` and `kid`
            if (!jwt.header.alg || !jwt.header.kid) {
                throw new Error('Signature verification failed: Expected JWS header to contain alg and kid');
            }
            const verificationResponse = yield verifyJWT(vcJwt, {
                resolver: dwnResolver
            });
            if (!verificationResponse.verified) {
                throw new Error('VC JWT could not be verified. Reason: ' + JSON.stringify(verificationResponse));
            }
        });
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
/**
 * Validates the structure and integrity of a Verifiable Credential payload.
 *
 * @param vc - The Verifiable Credential object to validate.
 * @throws Error if any validation check fails.
 */
export function validatePayload(vc) {
    VcValidator.validateContext(vc['@context']);
    VcValidator.validateVcType(vc.type);
    VcValidator.validateCredentialSubject(vc.credentialSubject);
    if (vc.issuanceDate)
        VcValidator.validateTimestamp(vc.issuanceDate);
    if (vc.expirationDate)
        VcValidator.validateTimestamp(vc.expirationDate);
}
/**
 * Decodes a VC JWT into its constituent parts: header, payload, and signature.
 *
 * @param jwt - The JWT string to decode.
 * @returns An object containing the decoded header, payload, and signature.
 */
export function decodeJwt(jwt) {
    const [encodedHeader, encodedPayload, encodedSignature] = jwt.split('.');
    if (!encodedHeader || !encodedPayload || !encodedSignature) {
        throw Error('Not a valid jwt');
    }
    return {
        header: Convert.base64Url(encodedHeader).toObject(),
        payload: Convert.base64Url(encodedPayload).toObject(),
        signature: encodedSignature
    };
}
/**
 * Create a VC JWT.
 *
 * @param payload - the payload for the JWT.
 * @param signOptions The sign options used to sign the credential.
 * @return The JWT representing the signed verifiable credential.
 */
export function createJwt(payload, signOptions) {
    return __awaiter(this, void 0, void 0, function* () {
        const { issuerDid, subjectDid, signer, kid } = signOptions;
        const header = { alg: 'EdDSA', typ: 'JWT', kid: kid };
        const jwtPayload = Object.assign({ iss: issuerDid, sub: subjectDid }, payload);
        const encodedHeader = Convert.object(header).toBase64Url();
        const encodedPayload = Convert.object(jwtPayload).toBase64Url();
        const message = encodedHeader + '.' + encodedPayload;
        const messageBytes = Convert.string(message).toUint8Array();
        const signature = yield signer(messageBytes);
        const encodedSignature = Convert.uint8Array(signature).toBase64Url();
        const jwt = message + '.' + encodedSignature;
        return jwt;
    });
}
//# sourceMappingURL=credential.js.map