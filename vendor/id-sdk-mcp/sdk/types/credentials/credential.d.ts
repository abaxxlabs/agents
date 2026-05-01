import type { ICredential, JwtDecodedVerifiableCredential } from '@sphereon/ssi-types';
export declare const DEFAULT_CONTEXT = "https://www.w3.org/2018/credentials/v1";
export declare const DEFAULT_VC_TYPE = "VerifiableCredential";
export declare const VC_DATA_FORMAT = "application/vc+jwt";
/**
 * A Verifiable Credential is a set of one or more claims made by the same entity.
 *
 * @see {@link https://www.w3.org/TR/vc-data-model/#credentials | VC Data Model}
 */
export type VcDataModel = ICredential;
/**
 * @param type Optional. The type of the credential, can be a string or an array of strings.
 * @param issuer The issuer URI of the credential, as a string.
 * @param subject The subject URI of the credential, as a string.
 * @param data The credential data, as a generic type any.
 * @param issuanceDate Optional. The issuance date of the credential, as a string.
 *               Defaults to the current date if not specified.
 * @param expirationDate Optional. The expiration date of the credential, as a string.
 * @param revocable Optional. Whether the credential should be revocable (adds credentialStatus).
 * @param suspendable Optional. Whether the credential should be suspendable (adds credentialStatus).
 * @param statusListCredentialId Optional. ID of existing status list credential to link to.
 */
export type VerifiableCredentialCreateOptions = {
    type?: string | string[];
    issuer: string;
    subject: string;
    data: any;
    issuanceDate?: string;
    expirationDate?: string;
    revocable?: boolean;
    suspendable?: boolean;
    statusListCredentialId?: string;
};
export type SignOptions = {
    kid: string;
    issuerDid: string;
    subjectDid: string;
    signer: Signer;
};
export type Signer = (data: Uint8Array) => Promise<Uint8Array>;
type JwtHeaderParams = {
    alg: string;
    typ: 'JWT';
    kid: string;
};
export type DecodedVcJwt = {
    header: JwtHeaderParams;
    payload: JwtDecodedVerifiableCredential;
    signature: string;
};
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
export declare class VerifiableCredential {
    vcDataModel: VcDataModel;
    constructor(vcDataModel: VcDataModel);
    get type(): string;
    get issuer(): string;
    get subject(): string;
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
    sign(signOptions: SignOptions): Promise<string>;
    /**
     * Converts the current object to its JSON representation.
     *
     * @return The JSON representation of the object.
     */
    toString(): string;
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
    static create(vcCreateOptions: VerifiableCredentialCreateOptions): VerifiableCredential;
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
    static verify(vcJwt: string): Promise<void>;
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
    static parseJwt(vcJwt: string): VerifiableCredential;
}
/**
 * Validates the structure and integrity of a Verifiable Credential payload.
 *
 * @param vc - The Verifiable Credential object to validate.
 * @throws Error if any validation check fails.
 */
export declare function validatePayload(vc: VcDataModel): void;
/**
 * Decodes a VC JWT into its constituent parts: header, payload, and signature.
 *
 * @param jwt - The JWT string to decode.
 * @returns An object containing the decoded header, payload, and signature.
 */
export declare function decodeJwt(jwt: string): DecodedVcJwt;
/**
 * Create a VC JWT.
 *
 * @param payload - the payload for the JWT.
 * @param signOptions The sign options used to sign the credential.
 * @return The JWT representing the signed verifiable credential.
 */
export declare function createJwt(payload: any, signOptions: SignOptions): Promise<string>;
export {};
//# sourceMappingURL=credential.d.ts.map