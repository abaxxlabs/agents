import type { IDAgent } from './agent/index.js';
import type { DwnApi } from './dwn-api.js';
import type { DecodedVcJwt, Signer } from './credentials/credential.js';
import type { DecodedVpJwt } from './credentials/presentation.js';
import type { PresentationSubmission } from '@sphereon/ssi-types';
import type { EvaluationResults, PresentationResult } from '@sphereon/pex';
import type { PresentationDefinitionV2 } from './credentials/presentation.js';
import type { VcDataModel } from './credentials/credential.js';
import type { BbsSignOptions, BbsDeriveProofOptions, BbsCredentialCreateOptions, BbsSignedCredentialBundle, BbsDerivedCredential, BbsVerifiableCredential } from './credentials/credential-bbs.js';
import type { BbsKeyPair } from './crypto/crypto-primitives/bbs.js';
import { SignOptions, VerifiableCredential } from './credentials/credential.js';
/**
 * The VC API is used to issue, present and verify VCs
 *
 * @beta
 */
export declare class VcApi {
    private agent;
    private connectedDid;
    private statusListManager?;
    private vcServiceUrl?;
    constructor(options: {
        agent: IDAgent;
        connectedDid: string;
        dwnApi?: DwnApi;
        vcServiceUrl?: string;
    });
    createCredential(issuer: string, subject: string, data: any, type?: string): Promise<VerifiableCredential>;
    signCredential(vc: VerifiableCredential, signOptions: SignOptions): Promise<any>;
    createJWT(payload: any, signOptions: SignOptions): Promise<any>;
    decodeJWT(jwt: string): Promise<DecodedVcJwt>;
    parseJWT(jwt: string): Promise<VerifiableCredential>;
    verifyJWT(jwt: string): Promise<boolean>;
    createPresentation(vcJwts: string[], presentationDefinition: PresentationDefinitionV2): Promise<PresentationResult>;
    satisfiesPresentation(vcJwts: string[], presentationDefinition: PresentationDefinitionV2): Promise<boolean>;
    decodePresentation(jwt: string): Promise<DecodedVpJwt>;
    evaluatePresentation(presentationDefinition: PresentationDefinitionV2, presentationResult: any): Promise<EvaluationResults>;
    validateSubmission(presentationSubmission: PresentationSubmission): Promise<any>;
    EdDsaSigner(privateKey: Uint8Array): Signer;
    /**
     * Create a revocable credential with status list support
     *
     * @param options - Options for creating a revocable credential
     * @returns Credential with status list information
     */
    createRevocableCredential(options: {
        issuer: string;
        subject: string;
        data: any;
        type?: string;
        revocable?: boolean;
        suspendable?: boolean;
        signOptions: SignOptions;
    }): Promise<{
        credential: VerifiableCredential;
        credentialJwt: string;
        statusListCredential?: VerifiableCredential;
        statusListJwt?: string;
        statusListRecordId?: string;
        credentialStatus?: any;
    }>;
    /**
     * Revoke a credential (SDK-native or via VC Service)
     *
     * @param options - Options for revoking the credential
     * @returns Revocation result
     */
    revokeCredential(options: {
        credentialId: string;
        statusListRecordId?: string;
        statusListIndex?: number;
        useService?: boolean;
        signOptions?: SignOptions;
    }): Promise<any>;
    /**
     * Suspend a credential (SDK-native or via VC Service)
     *
     * @param options - Options for suspending the credential
     * @returns Suspension result
     */
    suspendCredential(options: {
        credentialId: string;
        statusListRecordId?: string;
        statusListIndex?: number;
        useService?: boolean;
        signOptions?: SignOptions;
    }): Promise<any>;
    /**
     * Check credential status
     *
     * @param options - Options for checking status
     * @returns Status information
     */
    checkCredentialStatus(options: {
        credentialId: string;
        statusListCredentialId?: string;
        statusListIndex?: number;
        statusListRecordId?: string;
        useService?: boolean;
    }): Promise<{
        revoked: boolean;
        suspended: boolean;
    }>;
    /**
     * Revoke via VC Service API
     */
    private revokeViaService;
    /**
     * Suspend via VC Service API
     */
    private suspendViaService;
    /**
     * Check status via VC Service API
     */
    private checkStatusViaService;
    /**
     * Helper to get signer options from agent
     * This is a convenience method that can be used to get signer options
     */
    getSignerOptions(issuerDid: string, subjectDid: string): Promise<SignOptions>;
    /**
     * Generates a BLS12-381 G2 key pair for BBS+ signature operations.
     *
     * @returns A key pair with 96-byte publicKey and 32-byte secretKey.
     */
    generateBbsKeyPair(): Promise<BbsKeyPair>;
    /**
     * Creates a Verifiable Credential data model prepared for BBS+ signing.
     * Each attribute in `data` will become a separately-signable BBS+ message.
     */
    createBbsCredential(options: BbsCredentialCreateOptions): Promise<VcDataModel>;
    /**
     * Signs a credential with BBS+ producing a Data Integrity proof.
     * The credential subject attributes are signed as individual BBS+ messages,
     * enabling per-attribute selective disclosure.
     *
     * @param vc - The VC data model to sign.
     * @param signOptions - BBS+ signing options including the key pair.
     * @returns A bundle containing the signed credential, attribute key order, and signature.
     */
    signBbsCredential(vc: VcDataModel, signOptions: BbsSignOptions): Promise<BbsSignedCredentialBundle>;
    /**
     * Verifies a full BBS+ signed credential against the issuer's public key.
     *
     * @param credential - The BBS+ signed credential.
     * @param issuerPublicKey - The issuer's 96-byte BLS12-381 G2 public key.
     */
    verifyBbsCredential(credential: BbsVerifiableCredential, issuerPublicKey: Uint8Array): Promise<boolean>;
    /**
     * Derives a zero-knowledge selective disclosure proof from a BBS+ signed
     * credential. The result contains only the chosen attributes and a proof
     * that the holder possesses a valid signature over the full attribute set.
     *
     * @param bundle - The signed credential bundle (from signBbsCredential).
     * @param options - Which attributes to reveal and a session nonce.
     */
    deriveBbsSelectiveProof(bundle: BbsSignedCredentialBundle, options: BbsDeriveProofOptions): Promise<BbsDerivedCredential>;
    /**
     * Verifies a BBS+ selective disclosure proof. The verifier only sees the
     * disclosed attributes but can cryptographically confirm they originate
     * from a valid credential signed by the issuer.
     *
     * @param credential - The derived credential with selective disclosure proof.
     * @param issuerPublicKey - The issuer's 96-byte BLS12-381 G2 public key.
     */
    verifyBbsSelectiveProof(credential: BbsVerifiableCredential, issuerPublicKey: Uint8Array): Promise<boolean>;
    /**
     * Resolves the BBS+ public key from an issuer's DID document.
     *
     * @param issuerDid - The issuer's DID.
     * @param kid - Optional key ID to match a specific verification method.
     */
    resolveIssuerBbsPublicKey(issuerDid: string, kid?: string): Promise<Uint8Array | null>;
}
//# sourceMappingURL=vc-api.d.ts.map