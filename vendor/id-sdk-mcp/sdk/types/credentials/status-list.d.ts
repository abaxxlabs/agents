import type { IDAgent } from '../agent/index.js';
import type { DwnApi } from '../dwn-api.js';
import type { Record } from '../record.js';
import type { VerifiableCredential, SignOptions } from './credential.js';
/**
 * Constants for Status List 2021 implementation
 */
export declare const STATUS_LIST_DATA_FORMAT = "application/vc-status-list+jwt";
export declare const STATUS_LIST_SCHEMA = "StatusList2021Credential";
export declare const STATUS_LIST_CONTEXT = "https://w3id.org/vc/status-list/2021/v1";
/**
 * Status purpose types as per Status List 2021 spec
 */
export type StatusPurpose = 'revocation' | 'suspension';
/**
 * Options for creating a status list credential
 */
export type CreateStatusListOptions = {
    issuer: string;
    statusPurpose: StatusPurpose;
    signOptions: SignOptions;
    size?: number;
};
/**
 * Options for revoking a credential
 */
export type RevokeCredentialOptions = {
    credentialId: string;
    statusListRecordId: string;
    statusListIndex: number;
    signOptions: SignOptions;
};
/**
 * Options for checking credential status
 */
export type CheckStatusOptions = {
    statusListCredentialId: string;
    statusListIndex: number;
    statusListRecordId?: string;
};
/**
 * Status List 2021 implementation for credential revocation
 * Based on: https://w3c.github.io/vc-status-list-2021/
 *
 * @beta
 */
export declare class StatusListManager {
    private agent;
    private connectedDid;
    private dwnApi;
    constructor(options: {
        agent: IDAgent;
        connectedDid: string;
        dwnApi: DwnApi;
    });
    /**
     * Create a Status List Credential for tracking revocation/suspension status
     *
     * @param options - Options for creating the status list
     * @returns Status list credential and DWN record
     */
    createStatusList(options: CreateStatusListOptions): Promise<{
        statusListCredential: VerifiableCredential;
        statusListJwt: string;
        record: Record;
    }>;
    /**
     * Add credentialStatus to a credential, linking it to a status list
     *
     * @param vc - The verifiable credential to add status to
     * @param statusListCredentialId - The ID of the status list credential
     * @param statusListIndex - The index in the status list for this credential
     * @param statusPurpose - The purpose (revocation or suspension)
     * @returns The credential with credentialStatus added
     */
    addCredentialStatus(vc: VerifiableCredential, statusListCredentialId: string, statusListIndex: number, statusPurpose?: StatusPurpose): VerifiableCredential;
    /**
     * Revoke a credential by updating the status list bitstring
     *
     * @param options - Options for revoking the credential
     * @returns Updated status list credential and record
     */
    revokeCredential(options: RevokeCredentialOptions): Promise<{
        statusListCredential: VerifiableCredential;
        statusListJwt: string;
        record: Record;
    }>;
    /**
     * Suspend a credential by updating the status list bitstring
     *
     * @param options - Options for suspending the credential
     * @returns Updated status list credential and record
     */
    suspendCredential(options: RevokeCredentialOptions): Promise<{
        statusListCredential: VerifiableCredential;
        statusListJwt: string;
        record: Record;
    }>;
    /**
     * Check if a credential is revoked or suspended
     *
     * @param options - Options for checking status
     * @returns Status information
     */
    checkStatus(options: CheckStatusOptions): Promise<{
        revoked: boolean;
        suspended: boolean;
    }>;
    /**
     * Private method to update credential status in a status list
     */
    private updateCredentialStatus;
}
//# sourceMappingURL=status-list.d.ts.map