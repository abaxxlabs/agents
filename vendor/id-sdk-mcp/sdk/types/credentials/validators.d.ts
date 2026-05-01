import { VerifiableCredential } from './credential.js';
import type { ICredentialContextType, ICredentialSubject } from '@sphereon/ssi-types';
export declare class VcValidator {
    static validateCredentialPayload(vc: VerifiableCredential): void;
    static validateContext(value: ICredentialContextType | ICredentialContextType[]): void;
    static validateVcType(value: string | string[]): void;
    static validateCredentialSubject(value: ICredentialSubject | ICredentialSubject[]): void;
    static validateTimestamp(timestamp: string): void;
    static asArray(arg: any | any[]): any[];
}
//# sourceMappingURL=validators.d.ts.map