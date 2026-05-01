import type { ICredential } from '@sphereon/ssi-types';
import type { BbsKeyPair } from '../crypto/crypto-primitives/bbs.js';
import type { VcDataModel } from './credential.js';
export declare const VC_DATA_FORMAT_LDP = "application/vc+ld+json";
/**
 * BBS+ Data Integrity proof attached to a Verifiable Credential.
 */
export interface BbsDataIntegrityProof {
    type: 'DataIntegrityProof';
    cryptosuite: 'bbs-2023';
    verificationMethod: string;
    proofPurpose: 'assertionMethod';
    proofValue: string;
    created: string;
}
/**
 * A derived BBS+ selective disclosure proof.
 */
export interface BbsDerivedProof {
    type: 'DataIntegrityProof';
    cryptosuite: 'bbs-2023';
    verificationMethod: string;
    proofPurpose: 'assertionMethod';
    proofValue: string;
    nonce: string;
    created: string;
    disclosedIndices: number[];
}
/**
 * VC with a BBS+ Data Integrity proof (full or derived).
 */
export interface BbsVerifiableCredential extends ICredential {
    proof: BbsDataIntegrityProof | BbsDerivedProof;
}
/**
 * Options for signing a credential with BBS+.
 */
export interface BbsSignOptions {
    kid: string;
    issuerDid: string;
    subjectDid: string;
    keyPair: BbsKeyPair;
}
/**
 * Options for deriving a selective disclosure proof.
 */
export interface BbsDeriveProofOptions {
    issuerPublicKey: Uint8Array;
    revealedAttributes: string[];
    nonce: string;
}
/**
 * Options for creating a BBS+ credential.
 */
export interface BbsCredentialCreateOptions {
    type?: string | string[];
    issuer: string;
    subject: string;
    data: Record<string, any>;
    issuanceDate?: string;
    expirationDate?: string;
}
/**
 * Serialized representation of a BBS+ signed credential
 * containing the signed VC, the original message order, and the signature.
 */
export interface BbsSignedCredentialBundle {
    credential: BbsVerifiableCredential;
    messageKeys: string[];
    signature: string;
}
/**
 * Result of deriving a selective disclosure proof from a BBS+ credential.
 */
export interface BbsDerivedCredential {
    credential: BbsVerifiableCredential;
    disclosedKeys: string[];
    disclosedIndices: number[];
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
export declare class BbsCredential {
    /**
     * Creates a VC data model suitable for BBS+ signing.
     */
    static create(options: BbsCredentialCreateOptions): VcDataModel;
    /**
     * Signs a VC with BBS+. Each attribute in `credentialSubject` becomes a
     * separate BBS+ message, enabling per-attribute selective disclosure.
     *
     * @returns A bundle containing the signed credential, message key order,
     *          and base64url-encoded signature.
     */
    static sign(vcDataModel: VcDataModel, signOptions: BbsSignOptions): Promise<BbsSignedCredentialBundle>;
    /**
     * Verifies a full BBS+ signed credential (not a derived proof).
     * Reconstructs the message array from `credentialSubject` and verifies
     * the signature against the issuer's public key.
     *
     * @param credential - The BBS+ signed VC.
     * @param issuerPublicKey - The issuer's 96-byte BLS12-381 G2 public key.
     * @returns `true` if the signature is valid.
     */
    static verify(credential: BbsVerifiableCredential, issuerPublicKey: Uint8Array): Promise<boolean>;
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
    static deriveProof(bundle: BbsSignedCredentialBundle, options: BbsDeriveProofOptions): Promise<BbsDerivedCredential>;
    /**
     * Verifies a BBS+ selective disclosure proof. Only the disclosed messages
     * are checked against the proof — the verifier does not learn the values
     * of undisclosed attributes.
     *
     * @param credential - The derived credential containing a selective disclosure proof.
     * @param issuerPublicKey - The issuer's 96-byte BLS12-381 G2 public key.
     * @returns `true` if the proof is valid.
     */
    static verifyProof(credential: BbsVerifiableCredential, issuerPublicKey: Uint8Array): Promise<boolean>;
    /**
     * Resolves an issuer DID and attempts to extract the BBS+ public key
     * from the DID document's verification methods.
     *
     * @param issuerDid - The DID of the credential issuer.
     * @param kid - Optional key ID fragment to match a specific verification method.
     * @returns The BLS12-381 G2 public key as Uint8Array, or null if not found.
     */
    static resolveIssuerPublicKey(issuerDid: string, kid?: string): Promise<Uint8Array | null>;
}
//# sourceMappingURL=credential-bbs.d.ts.map