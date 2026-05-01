var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { VerifiableCredential as VC } from './credential.js';
import { v4 as uuidv4 } from 'uuid';
import { Convert } from '../common/index.js';
import pako from 'pako';
/**
 * Constants for Status List 2021 implementation
 */
export const STATUS_LIST_DATA_FORMAT = 'application/vc-status-list+jwt';
export const STATUS_LIST_SCHEMA = 'StatusList2021Credential';
export const STATUS_LIST_CONTEXT = 'https://w3id.org/vc/status-list/2021/v1';
/**
 * Status List 2021 implementation for credential revocation
 * Based on: https://w3c.github.io/vc-status-list-2021/
 *
 * @beta
 */
export class StatusListManager {
    constructor(options) {
        this.agent = options.agent;
        this.connectedDid = options.connectedDid;
        this.dwnApi = options.dwnApi;
    }
    /**
     * Create a Status List Credential for tracking revocation/suspension status
     *
     * @param options - Options for creating the status list
     * @returns Status list credential and DWN record
     */
    createStatusList(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const { issuer, statusPurpose, signOptions, size = 131072 } = options;
            // Create empty bitstring (all zeros = no credentials revoked)
            const bitstring = new Uint8Array(Math.ceil(size / 8));
            bitstring.fill(0);
            // Compress bitstring with gzip
            const compressed = pako.gzip(bitstring);
            // Base64url encode the compressed bitstring
            const encodedList = Convert.uint8Array(compressed).toBase64Url();
            // Create status list credential subject
            const statusListId = `urn:uuid:${uuidv4()}`;
            const credentialSubject = {
                id: `${statusListId}#list`,
                type: 'StatusList2021',
                statusPurpose: statusPurpose,
                encodedList: encodedList
            };
            // Create the status list credential
            // Note: The subject for a status list credential is the list itself
            // The subject parameter will be overridden by the id in credentialSubject data
            const statusListCredential = VC.create({
                issuer: issuer,
                subject: statusListId,
                data: credentialSubject,
                type: 'StatusList2021Credential'
            });
            // Add Status List context
            statusListCredential.vcDataModel['@context'] = [
                'https://www.w3.org/2018/credentials/v1',
                STATUS_LIST_CONTEXT
            ];
            // Update type to include StatusList2021Credential
            statusListCredential.vcDataModel.type = [
                'VerifiableCredential',
                'StatusList2021Credential'
            ];
            // Set the ID
            statusListCredential.vcDataModel.id = statusListId;
            // Sign the status list credential
            const statusListJwt = yield statusListCredential.sign(signOptions);
            // Store in DWN
            const { record } = yield this.dwnApi.records.create({
                data: statusListJwt,
                message: {
                    schema: STATUS_LIST_SCHEMA,
                    dataFormat: STATUS_LIST_DATA_FORMAT,
                },
            });
            return {
                statusListCredential,
                statusListJwt,
                record
            };
        });
    }
    /**
     * Add credentialStatus to a credential, linking it to a status list
     *
     * @param vc - The verifiable credential to add status to
     * @param statusListCredentialId - The ID of the status list credential
     * @param statusListIndex - The index in the status list for this credential
     * @param statusPurpose - The purpose (revocation or suspension)
     * @returns The credential with credentialStatus added
     */
    addCredentialStatus(vc, statusListCredentialId, statusListIndex, statusPurpose = 'revocation') {
        const credentialStatus = {
            id: `${statusListCredentialId}#${statusListIndex}`,
            type: 'StatusList2021Entry',
            statusPurpose: statusPurpose,
            statusListIndex: statusListIndex.toString(),
            statusListCredential: statusListCredentialId
        };
        // Add credentialStatus to the VC
        vc.vcDataModel.credentialStatus = credentialStatus;
        // Add Status List context if not already present
        const contexts = Array.isArray(vc.vcDataModel['@context'])
            ? vc.vcDataModel['@context']
            : [vc.vcDataModel['@context']];
        if (!contexts.includes(STATUS_LIST_CONTEXT)) {
            vc.vcDataModel['@context'] = [...contexts, STATUS_LIST_CONTEXT];
        }
        return vc;
    }
    /**
     * Revoke a credential by updating the status list bitstring
     *
     * @param options - Options for revoking the credential
     * @returns Updated status list credential and record
     */
    revokeCredential(options) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.updateCredentialStatus(Object.assign(Object.assign({}, options), { revoked: true }));
        });
    }
    /**
     * Suspend a credential by updating the status list bitstring
     *
     * @param options - Options for suspending the credential
     * @returns Updated status list credential and record
     */
    suspendCredential(options) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.updateCredentialStatus(Object.assign(Object.assign({}, options), { revoked: true // Suspension also sets the bit to 1
             }));
        });
    }
    /**
     * Check if a credential is revoked or suspended
     *
     * @param options - Options for checking status
     * @returns Status information
     */
    checkStatus(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const { statusListCredentialId, statusListIndex, statusListRecordId } = options;
            let statusListJwt;
            // Resolve status list credential
            if (statusListRecordId) {
                // Read from DWN
                const { record } = yield this.dwnApi.records.read({
                    message: {
                        filter: {
                            recordId: statusListRecordId
                        }
                    }
                });
                statusListJwt = yield record.data.text();
            }
            else {
                // Try to resolve from URL (external status list)
                // For now, we'll require statusListRecordId for SDK-native status lists
                throw new Error('statusListRecordId is required for DWN-based status lists');
            }
            // Parse the status list credential
            const statusListVc = VC.parseJwt(statusListJwt);
            const credentialSubject = statusListVc.vcDataModel.credentialSubject;
            if (!credentialSubject || !credentialSubject.encodedList) {
                throw new Error('Invalid status list credential: missing encodedList');
            }
            // Decode and decompress the bitstring
            const encodedList = credentialSubject.encodedList;
            const compressed = Convert.base64Url(encodedList).toUint8Array();
            const bitstring = pako.ungzip(compressed);
            // Check the bit at the specified index
            const byteIndex = Math.floor(statusListIndex / 8);
            const bitIndex = statusListIndex % 8;
            if (byteIndex >= bitstring.length) {
                throw new Error(`Status list index ${statusListIndex} is out of bounds`);
            }
            const byte = bitstring[byteIndex];
            const bit = (byte >> bitIndex) & 1;
            const isRevoked = bit === 1;
            // Determine if it's revocation or suspension based on statusPurpose
            const statusPurpose = credentialSubject.statusPurpose;
            const revoked = isRevoked && statusPurpose === 'revocation';
            const suspended = isRevoked && statusPurpose === 'suspension';
            return { revoked, suspended };
        });
    }
    /**
     * Private method to update credential status in a status list
     */
    updateCredentialStatus(options) {
        return __awaiter(this, void 0, void 0, function* () {
            const { statusListRecordId, statusListIndex, signOptions, revoked } = options;
            // Read the existing status list record
            const { record } = yield this.dwnApi.records.read({
                message: {
                    filter: {
                        recordId: statusListRecordId
                    }
                }
            });
            const statusListJwt = yield record.data.text();
            const statusListVc = VC.parseJwt(statusListJwt);
            // Get the credential subject
            const credentialSubject = statusListVc.vcDataModel.credentialSubject;
            if (!credentialSubject || !credentialSubject.encodedList) {
                throw new Error('Invalid status list credential: missing encodedList');
            }
            // Decode and decompress the bitstring
            const encodedList = credentialSubject.encodedList;
            const compressed = Convert.base64Url(encodedList).toUint8Array();
            const bitstring = pako.ungzip(compressed);
            // Update the bit at the specified index
            const byteIndex = Math.floor(statusListIndex / 8);
            const bitIndex = statusListIndex % 8;
            if (byteIndex >= bitstring.length) {
                throw new Error(`Status list index ${statusListIndex} is out of bounds`);
            }
            // Set or clear the bit
            if (revoked) {
                bitstring[byteIndex] |= (1 << bitIndex); // Set bit to 1
            }
            else {
                bitstring[byteIndex] &= ~(1 << bitIndex); // Clear bit to 0
            }
            // Re-compress and encode
            const newCompressed = pako.gzip(bitstring);
            const newEncodedList = Convert.uint8Array(newCompressed).toBase64Url();
            // Update the credential subject
            credentialSubject.encodedList = newEncodedList;
            // Create updated status list credential
            const updatedStatusListVc = VC.create({
                issuer: statusListVc.issuer,
                subject: statusListVc.vcDataModel.id || `urn:uuid:${uuidv4()}`,
                data: credentialSubject,
                type: 'StatusList2021Credential'
            });
            // Preserve context and type
            updatedStatusListVc.vcDataModel['@context'] = statusListVc.vcDataModel['@context'];
            updatedStatusListVc.vcDataModel.type = statusListVc.vcDataModel.type;
            updatedStatusListVc.vcDataModel.id = statusListVc.vcDataModel.id;
            // Sign the updated credential
            const updatedStatusListJwt = yield updatedStatusListVc.sign(signOptions);
            // Update the DWN record
            yield record.update({
                data: updatedStatusListJwt
            });
            return {
                statusListCredential: updatedStatusListVc,
                statusListJwt: updatedStatusListJwt,
                record
            };
        });
    }
}
//# sourceMappingURL=status-list.js.map