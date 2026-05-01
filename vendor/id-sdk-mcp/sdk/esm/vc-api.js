var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { Convert } from './common/index.js';
import { Ed25519, Bbs } from './crypto/index.js';
import { createJwt, decodeJwt, VerifiableCredential } from './credentials/credential.js';
import { BbsCredential } from './credentials/credential-bbs.js';
import { PresentationExchange } from './credentials/presentation.js';
import { StatusListManager } from './credentials/status-list.js';
/**
 * The VC API is used to issue, present and verify VCs
 *
 * @beta
 */
export class VcApi {
    constructor(options) {
        this.agent = options.agent;
        this.connectedDid = options.connectedDid;
        if (options.dwnApi) {
            this.statusListManager = new StatusListManager({
                agent: options.agent,
                connectedDid: options.connectedDid,
                dwnApi: options.dwnApi
            });
        }
        this.vcServiceUrl = options.vcServiceUrl;
    }
    createCredential(issuer, subject, data, type) {
        return __awaiter(this, void 0, void 0, function* () {
            const vc = VerifiableCredential.create({
                issuer,
                subject,
                data,
                type,
            });
            return vc;
        });
    }
    signCredential(vc, signOptions) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield vc.sign(signOptions);
        });
    }
    createJWT(payload, signOptions) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield createJwt(payload, signOptions);
        });
    }
    decodeJWT(jwt) {
        return __awaiter(this, void 0, void 0, function* () {
            return decodeJwt(jwt);
        });
    }
    parseJWT(jwt) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield VerifiableCredential.parseJwt(jwt);
        });
    }
    verifyJWT(jwt) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                VerifiableCredential.verify(jwt);
                return true;
            }
            catch (e) {
                console.log('verifyJWT error', e);
                return false;
            }
        });
    }
    createPresentation(vcJwts, presentationDefinition) {
        return __awaiter(this, void 0, void 0, function* () {
            return PresentationExchange.createPresentationFromCredentials(vcJwts, presentationDefinition);
        });
    }
    satisfiesPresentation(vcJwts, presentationDefinition) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                PresentationExchange.validateDefinition(presentationDefinition);
                PresentationExchange.satisfiesPresentationDefinition(vcJwts, presentationDefinition);
                return true;
            }
            catch (err) {
                return false;
            }
        });
    }
    decodePresentation(jwt) {
        return __awaiter(this, void 0, void 0, function* () {
            const [encodedHeader, encodedPayload, encodedSignature] = jwt.split('.');
            return {
                header: Convert.base64Url(encodedHeader).toObject(),
                payload: Convert.base64Url(encodedPayload).toObject(),
                signature: encodedSignature
            };
        });
    }
    evaluatePresentation(presentationDefinition, presentationResult) {
        return __awaiter(this, void 0, void 0, function* () {
            return PresentationExchange.evaluatePresentation(presentationDefinition, presentationResult.presentation);
        });
    }
    validateSubmission(presentationSubmission) {
        return __awaiter(this, void 0, void 0, function* () {
            return PresentationExchange.validateSubmission(presentationSubmission);
        });
    }
    EdDsaSigner(privateKey) {
        return (data) => __awaiter(this, void 0, void 0, function* () {
            const signature = yield Ed25519.sign({ data, key: privateKey });
            return signature;
        });
    }
    /**
     * Create a revocable credential with status list support
     *
     * @param options - Options for creating a revocable credential
     * @returns Credential with status list information
     */
    createRevocableCredential(options) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!this.statusListManager) {
                throw new Error('StatusListManager not available. Provide dwnApi in VcApi constructor.');
            }
            const { issuer, subject, data, type, revocable, suspendable, signOptions } = options;
            // Create base credential
            const credential = yield this.createCredential(issuer, subject, data, type);
            // If revocable or suspendable, create or get status list
            if (revocable || suspendable) {
                const statusPurpose = revocable ? 'revocation' : 'suspension';
                // Create a new status list (in production, you might want to reuse existing ones)
                const { statusListCredential, statusListJwt, record } = yield this.statusListManager.createStatusList({
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
                const credentialJwt = yield credential.sign(signOptions);
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
                const credentialJwt = yield credential.sign(signOptions);
                return {
                    credential,
                    credentialJwt
                };
            }
        });
    }
    /**
     * Revoke a credential (SDK-native or via VC Service)
     *
     * @param options - Options for revoking the credential
     * @returns Revocation result
     */
    revokeCredential(options) {
        return __awaiter(this, void 0, void 0, function* () {
            if (options.useService && this.vcServiceUrl) {
                // Call VC Service API
                return yield this.revokeViaService(options.credentialId);
            }
            else if (this.statusListManager && options.statusListRecordId && options.statusListIndex !== undefined && options.signOptions) {
                // Use SDK-native revocation
                return yield this.statusListManager.revokeCredential({
                    credentialId: options.credentialId,
                    statusListRecordId: options.statusListRecordId,
                    statusListIndex: options.statusListIndex,
                    signOptions: options.signOptions
                });
            }
            else {
                throw new Error('Either useService=true with vcServiceUrl, or statusListRecordId, statusListIndex, and signOptions must be provided for SDK-native revocation');
            }
        });
    }
    /**
     * Suspend a credential (SDK-native or via VC Service)
     *
     * @param options - Options for suspending the credential
     * @returns Suspension result
     */
    suspendCredential(options) {
        return __awaiter(this, void 0, void 0, function* () {
            if (options.useService && this.vcServiceUrl) {
                // Call VC Service API (suspension via service)
                return yield this.suspendViaService(options.credentialId);
            }
            else if (this.statusListManager && options.statusListRecordId && options.statusListIndex !== undefined && options.signOptions) {
                // Use SDK-native suspension
                return yield this.statusListManager.suspendCredential({
                    credentialId: options.credentialId,
                    statusListRecordId: options.statusListRecordId,
                    statusListIndex: options.statusListIndex,
                    signOptions: options.signOptions
                });
            }
            else {
                throw new Error('Either useService=true with vcServiceUrl, or statusListRecordId, statusListIndex, and signOptions must be provided for SDK-native suspension');
            }
        });
    }
    /**
     * Check credential status
     *
     * @param options - Options for checking status
     * @returns Status information
     */
    checkCredentialStatus(options) {
        return __awaiter(this, void 0, void 0, function* () {
            if (options.useService && this.vcServiceUrl) {
                return yield this.checkStatusViaService(options.credentialId);
            }
            else if (options.statusListCredentialId && options.statusListIndex !== undefined && this.statusListManager) {
                return yield this.statusListManager.checkStatus({
                    statusListCredentialId: options.statusListCredentialId,
                    statusListIndex: options.statusListIndex,
                    statusListRecordId: options.statusListRecordId
                });
            }
            else {
                throw new Error('Either useService=true with vcServiceUrl, or statusListCredentialId and statusListIndex must be provided');
            }
        });
    }
    /**
     * Revoke via VC Service API
     */
    revokeViaService(credentialId) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!this.vcServiceUrl) {
                throw new Error('vcServiceUrl not configured');
            }
            const response = yield fetch(`${this.vcServiceUrl}/v1/credentials/${credentialId}/status`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ revoked: true })
            });
            if (!response.ok) {
                throw new Error(`VC Service API error: ${response.status} ${response.statusText}`);
            }
            return yield response.json();
        });
    }
    /**
     * Suspend via VC Service API
     */
    suspendViaService(credentialId) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!this.vcServiceUrl) {
                throw new Error('vcServiceUrl not configured');
            }
            const response = yield fetch(`${this.vcServiceUrl}/v1/credentials/${credentialId}/status`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ suspended: true })
            });
            if (!response.ok) {
                throw new Error(`VC Service API error: ${response.status} ${response.statusText}`);
            }
            return yield response.json();
        });
    }
    /**
     * Check status via VC Service API
     */
    checkStatusViaService(credentialId) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!this.vcServiceUrl) {
                throw new Error('vcServiceUrl not configured');
            }
            const response = yield fetch(`${this.vcServiceUrl}/v1/credentials/${credentialId}/status`);
            if (!response.ok) {
                throw new Error(`VC Service API error: ${response.status} ${response.statusText}`);
            }
            return yield response.json();
        });
    }
    /**
     * Helper to get signer options from agent
     * This is a convenience method that can be used to get signer options
     */
    getSignerOptions(issuerDid, subjectDid) {
        return __awaiter(this, void 0, void 0, function* () {
            // Check if agent is IDManagedAgent (has didManager and dwnManager)
            if (!('didManager' in this.agent) || !('dwnManager' in this.agent)) {
                throw new Error('Agent must be an IDManagedAgent to get signer options');
            }
            const managedAgent = this.agent;
            // Get signing key ID from agent
            const signingKeyId = yield managedAgent.didManager.getDefaultSigningKey({ did: issuerDid });
            if (!signingKeyId) {
                throw new Error(`No signing key found for DID: ${issuerDid}`);
            }
            // Get the signer from agent
            const signer = yield managedAgent.dwnManager.getSigner(issuerDid);
            return {
                kid: signingKeyId,
                issuerDid: issuerDid,
                subjectDid: subjectDid,
                signer: signer.sign
            };
        });
    }
    // ──────────────────────────────────────────────────────
    // BBS+ Selective Disclosure Methods
    // ──────────────────────────────────────────────────────
    /**
     * Generates a BLS12-381 G2 key pair for BBS+ signature operations.
     *
     * @returns A key pair with 96-byte publicKey and 32-byte secretKey.
     */
    generateBbsKeyPair() {
        return __awaiter(this, void 0, void 0, function* () {
            return Bbs.generateKeyPair();
        });
    }
    /**
     * Creates a Verifiable Credential data model prepared for BBS+ signing.
     * Each attribute in `data` will become a separately-signable BBS+ message.
     */
    createBbsCredential(options) {
        return __awaiter(this, void 0, void 0, function* () {
            return BbsCredential.create(options);
        });
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
    signBbsCredential(vc, signOptions) {
        return __awaiter(this, void 0, void 0, function* () {
            return BbsCredential.sign(vc, signOptions);
        });
    }
    /**
     * Verifies a full BBS+ signed credential against the issuer's public key.
     *
     * @param credential - The BBS+ signed credential.
     * @param issuerPublicKey - The issuer's 96-byte BLS12-381 G2 public key.
     */
    verifyBbsCredential(credential, issuerPublicKey) {
        return __awaiter(this, void 0, void 0, function* () {
            return BbsCredential.verify(credential, issuerPublicKey);
        });
    }
    /**
     * Derives a zero-knowledge selective disclosure proof from a BBS+ signed
     * credential. The result contains only the chosen attributes and a proof
     * that the holder possesses a valid signature over the full attribute set.
     *
     * @param bundle - The signed credential bundle (from signBbsCredential).
     * @param options - Which attributes to reveal and a session nonce.
     */
    deriveBbsSelectiveProof(bundle, options) {
        return __awaiter(this, void 0, void 0, function* () {
            return BbsCredential.deriveProof(bundle, options);
        });
    }
    /**
     * Verifies a BBS+ selective disclosure proof. The verifier only sees the
     * disclosed attributes but can cryptographically confirm they originate
     * from a valid credential signed by the issuer.
     *
     * @param credential - The derived credential with selective disclosure proof.
     * @param issuerPublicKey - The issuer's 96-byte BLS12-381 G2 public key.
     */
    verifyBbsSelectiveProof(credential, issuerPublicKey) {
        return __awaiter(this, void 0, void 0, function* () {
            return BbsCredential.verifyProof(credential, issuerPublicKey);
        });
    }
    /**
     * Resolves the BBS+ public key from an issuer's DID document.
     *
     * @param issuerDid - The issuer's DID.
     * @param kid - Optional key ID to match a specific verification method.
     */
    resolveIssuerBbsPublicKey(issuerDid, kid) {
        return __awaiter(this, void 0, void 0, function* () {
            return BbsCredential.resolveIssuerPublicKey(issuerDid, kid);
        });
    }
}
//# sourceMappingURL=vc-api.js.map