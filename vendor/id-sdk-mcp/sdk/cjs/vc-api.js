"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.VcApi = void 0;
const index_js_1 = require("./common/index.js");
const index_js_2 = require("./crypto/index.js");
const credential_js_1 = require("./credentials/credential.js");
const credential_bbs_js_1 = require("./credentials/credential-bbs.js");
const presentation_js_1 = require("./credentials/presentation.js");
const status_list_js_1 = require("./credentials/status-list.js");
/**
 * The VC API is used to issue, present and verify VCs
 *
 * @beta
 */
class VcApi {
    constructor(options) {
        this.agent = options.agent;
        this.connectedDid = options.connectedDid;
        if (options.dwnApi) {
            this.statusListManager = new status_list_js_1.StatusListManager({
                agent: options.agent,
                connectedDid: options.connectedDid,
                dwnApi: options.dwnApi
            });
        }
        this.vcServiceUrl = options.vcServiceUrl;
    }
    async createCredential(issuer, subject, data, type) {
        const vc = credential_js_1.VerifiableCredential.create({
            issuer,
            subject,
            data,
            type,
        });
        return vc;
    }
    async signCredential(vc, signOptions) {
        return await vc.sign(signOptions);
    }
    async createJWT(payload, signOptions) {
        return await (0, credential_js_1.createJwt)(payload, signOptions);
    }
    async decodeJWT(jwt) {
        return (0, credential_js_1.decodeJwt)(jwt);
    }
    async parseJWT(jwt) {
        return await credential_js_1.VerifiableCredential.parseJwt(jwt);
    }
    async verifyJWT(jwt) {
        try {
            await credential_js_1.VerifiableCredential.verify(jwt);
            return true;
        }
        catch (e) {
            console.log('verifyJWT error', e);
            return false;
        }
    }
    async createPresentation(vcJwts, presentationDefinition) {
        return presentation_js_1.PresentationExchange.createPresentationFromCredentials(vcJwts, presentationDefinition);
    }
    async satisfiesPresentation(vcJwts, presentationDefinition) {
        try {
            presentation_js_1.PresentationExchange.validateDefinition(presentationDefinition);
            presentation_js_1.PresentationExchange.satisfiesPresentationDefinition(vcJwts, presentationDefinition);
            return true;
        }
        catch (err) {
            return false;
        }
    }
    async decodePresentation(jwt) {
        const [encodedHeader, encodedPayload, encodedSignature] = jwt.split('.');
        return {
            header: index_js_1.Convert.base64Url(encodedHeader).toObject(),
            payload: index_js_1.Convert.base64Url(encodedPayload).toObject(),
            signature: encodedSignature
        };
    }
    async evaluatePresentation(presentationDefinition, presentationResult) {
        return presentation_js_1.PresentationExchange.evaluatePresentation(presentationDefinition, presentationResult.presentation);
    }
    async validateSubmission(presentationSubmission) {
        return presentation_js_1.PresentationExchange.validateSubmission(presentationSubmission);
    }
    EdDsaSigner(privateKey) {
        return async (data) => {
            const signature = await index_js_2.Ed25519.sign({ data, key: privateKey });
            return signature;
        };
    }
    /**
     * Create a revocable credential with status list support
     *
     * @param options - Options for creating a revocable credential
     * @returns Credential with status list information
     */
    async createRevocableCredential(options) {
        if (!this.statusListManager) {
            throw new Error('StatusListManager not available. Provide dwnApi in VcApi constructor.');
        }
        const { issuer, subject, data, type, revocable, suspendable, signOptions } = options;
        // Create base credential
        const credential = await this.createCredential(issuer, subject, data, type);
        // If revocable or suspendable, create or get status list
        if (revocable || suspendable) {
            const statusPurpose = revocable ? 'revocation' : 'suspension';
            // Create a new status list (in production, you might want to reuse existing ones)
            const { statusListCredential, statusListJwt, record } = await this.statusListManager.createStatusList({
                issuer: issuer,
                statusPurpose: statusPurpose,
                signOptions: signOptions
            });
            // Generate a random index for this credential in the status list
            // In production, you'd want to track this index properly
            const statusListIndex = Math.floor(Math.random() * 100000); // Simplified - should be tracked
            // Add credentialStatus to the credential
            this.statusListManager.addCredentialStatus(credential, statusListCredential.vcDataModel.id, statusListIndex, statusPurpose);
            // Sign the credential with status
            const credentialJwt = await credential.sign(signOptions);
            return {
                credential,
                credentialJwt,
                statusListCredential,
                statusListJwt,
                statusListRecordId: record.id,
                credentialStatus: credential.vcDataModel.credentialStatus
            };
        }
        else {
            // Regular non-revocable credential
            const credentialJwt = await credential.sign(signOptions);
            return {
                credential,
                credentialJwt
            };
        }
    }
    /**
     * Revoke a credential (SDK-native or via VC Service)
     *
     * @param options - Options for revoking the credential
     * @returns Revocation result
     */
    async revokeCredential(options) {
        if (options.useService && this.vcServiceUrl) {
            // Call VC Service API
            return await this.revokeViaService(options.credentialId);
        }
        else if (this.statusListManager && options.statusListRecordId && options.statusListIndex !== undefined && options.signOptions) {
            // Use SDK-native revocation
            return await this.statusListManager.revokeCredential({
                credentialId: options.credentialId,
                statusListRecordId: options.statusListRecordId,
                statusListIndex: options.statusListIndex,
                signOptions: options.signOptions
            });
        }
        else {
            throw new Error('Either useService=true with vcServiceUrl, or statusListRecordId, statusListIndex, and signOptions must be provided for SDK-native revocation');
        }
    }
    /**
     * Suspend a credential (SDK-native or via VC Service)
     *
     * @param options - Options for suspending the credential
     * @returns Suspension result
     */
    async suspendCredential(options) {
        if (options.useService && this.vcServiceUrl) {
            // Call VC Service API (suspension via service)
            return await this.suspendViaService(options.credentialId);
        }
        else if (this.statusListManager && options.statusListRecordId && options.statusListIndex !== undefined && options.signOptions) {
            // Use SDK-native suspension
            return await this.statusListManager.suspendCredential({
                credentialId: options.credentialId,
                statusListRecordId: options.statusListRecordId,
                statusListIndex: options.statusListIndex,
                signOptions: options.signOptions
            });
        }
        else {
            throw new Error('Either useService=true with vcServiceUrl, or statusListRecordId, statusListIndex, and signOptions must be provided for SDK-native suspension');
        }
    }
    /**
     * Check credential status
     *
     * @param options - Options for checking status
     * @returns Status information
     */
    async checkCredentialStatus(options) {
        if (options.useService && this.vcServiceUrl) {
            return await this.checkStatusViaService(options.credentialId);
        }
        else if (options.statusListCredentialId && options.statusListIndex !== undefined && this.statusListManager) {
            return await this.statusListManager.checkStatus({
                statusListCredentialId: options.statusListCredentialId,
                statusListIndex: options.statusListIndex,
                statusListRecordId: options.statusListRecordId
            });
        }
        else {
            throw new Error('Either useService=true with vcServiceUrl, or statusListCredentialId and statusListIndex must be provided');
        }
    }
    /**
     * Revoke via VC Service API
     */
    async revokeViaService(credentialId) {
        if (!this.vcServiceUrl) {
            throw new Error('vcServiceUrl not configured');
        }
        const response = await fetch(`${this.vcServiceUrl}/v1/credentials/${credentialId}/status`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ revoked: true })
        });
        if (!response.ok) {
            throw new Error(`VC Service API error: ${response.status} ${response.statusText}`);
        }
        return await response.json();
    }
    /**
     * Suspend via VC Service API
     */
    async suspendViaService(credentialId) {
        if (!this.vcServiceUrl) {
            throw new Error('vcServiceUrl not configured');
        }
        const response = await fetch(`${this.vcServiceUrl}/v1/credentials/${credentialId}/status`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ suspended: true })
        });
        if (!response.ok) {
            throw new Error(`VC Service API error: ${response.status} ${response.statusText}`);
        }
        return await response.json();
    }
    /**
     * Check status via VC Service API
     */
    async checkStatusViaService(credentialId) {
        if (!this.vcServiceUrl) {
            throw new Error('vcServiceUrl not configured');
        }
        const response = await fetch(`${this.vcServiceUrl}/v1/credentials/${credentialId}/status`);
        if (!response.ok) {
            throw new Error(`VC Service API error: ${response.status} ${response.statusText}`);
        }
        return await response.json();
    }
    /**
     * Helper to get signer options from agent
     * This is a convenience method that can be used to get signer options
     */
    async getSignerOptions(issuerDid, subjectDid) {
        // Check if agent is IDManagedAgent (has didManager and dwnManager)
        if (!('didManager' in this.agent) || !('dwnManager' in this.agent)) {
            throw new Error('Agent must be an IDManagedAgent to get signer options');
        }
        const managedAgent = this.agent;
        // Get signing key ID from agent
        const signingKeyId = await managedAgent.didManager.getDefaultSigningKey({ did: issuerDid });
        if (!signingKeyId) {
            throw new Error(`No signing key found for DID: ${issuerDid}`);
        }
        // Get the signer from agent
        const signer = await managedAgent.dwnManager.getSigner(issuerDid);
        return {
            kid: signingKeyId,
            issuerDid: issuerDid,
            subjectDid: subjectDid,
            signer: signer.sign
        };
    }
    // ──────────────────────────────────────────────────────
    // BBS+ Selective Disclosure Methods
    // ──────────────────────────────────────────────────────
    /**
     * Generates a BLS12-381 G2 key pair for BBS+ signature operations.
     *
     * @returns A key pair with 96-byte publicKey and 32-byte secretKey.
     */
    async generateBbsKeyPair() {
        return index_js_2.Bbs.generateKeyPair();
    }
    /**
     * Creates a Verifiable Credential data model prepared for BBS+ signing.
     * Each attribute in `data` will become a separately-signable BBS+ message.
     */
    async createBbsCredential(options) {
        return credential_bbs_js_1.BbsCredential.create(options);
    }
    /**
     * Signs a credential with BBS+ producing a Data Integrity proof.
     * The credential subject attributes are signed as individual BBS+ messages,
     * enabling per-attribute selective disclosure.
     *
     * @param vc - The VC data model to sign.
     * @param signOptions - BBS+ signing options including the key pair.
     * @returns A bundle containing the signed credential, attribute key order, and signature.
     */
    async signBbsCredential(vc, signOptions) {
        return credential_bbs_js_1.BbsCredential.sign(vc, signOptions);
    }
    /**
     * Verifies a full BBS+ signed credential against the issuer's public key.
     *
     * @param credential - The BBS+ signed credential.
     * @param issuerPublicKey - The issuer's 96-byte BLS12-381 G2 public key.
     */
    async verifyBbsCredential(credential, issuerPublicKey) {
        return credential_bbs_js_1.BbsCredential.verify(credential, issuerPublicKey);
    }
    /**
     * Derives a zero-knowledge selective disclosure proof from a BBS+ signed
     * credential. The result contains only the chosen attributes and a proof
     * that the holder possesses a valid signature over the full attribute set.
     *
     * @param bundle - The signed credential bundle (from signBbsCredential).
     * @param options - Which attributes to reveal and a session nonce.
     */
    async deriveBbsSelectiveProof(bundle, options) {
        return credential_bbs_js_1.BbsCredential.deriveProof(bundle, options);
    }
    /**
     * Verifies a BBS+ selective disclosure proof. The verifier only sees the
     * disclosed attributes but can cryptographically confirm they originate
     * from a valid credential signed by the issuer.
     *
     * @param credential - The derived credential with selective disclosure proof.
     * @param issuerPublicKey - The issuer's 96-byte BLS12-381 G2 public key.
     */
    async verifyBbsSelectiveProof(credential, issuerPublicKey) {
        return credential_bbs_js_1.BbsCredential.verifyProof(credential, issuerPublicKey);
    }
    /**
     * Resolves the BBS+ public key from an issuer's DID document.
     *
     * @param issuerDid - The issuer's DID.
     * @param kid - Optional key ID to match a specific verification method.
     */
    async resolveIssuerBbsPublicKey(issuerDid, kid) {
        return credential_bbs_js_1.BbsCredential.resolveIssuerPublicKey(issuerDid, kid);
    }
}
exports.VcApi = VcApi;
//# sourceMappingURL=vc-api.js.map