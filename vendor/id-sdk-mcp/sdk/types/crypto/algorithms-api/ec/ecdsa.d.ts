import type { IDCrypto } from '../../types/iddwn-crypto.js';
import { BaseEllipticCurveAlgorithm } from './base.js';
export declare abstract class BaseEcdsaAlgorithm extends BaseEllipticCurveAlgorithm {
    readonly name: string;
    abstract readonly hashAlgorithms: string[];
    readonly keyUsages: IDCrypto.KeyPairUsage;
    checkAlgorithmOptions(options: {
        algorithm: IDCrypto.EcdsaOptions;
    }): void;
    deriveBits(): Promise<Uint8Array>;
    abstract sign(options: {
        algorithm: IDCrypto.EcdsaOptions;
        key: IDCrypto.CryptoKey;
        data: Uint8Array;
    }): Promise<Uint8Array>;
    abstract verify(options: {
        algorithm: IDCrypto.EcdsaOptions;
        key: IDCrypto.CryptoKey;
        signature: Uint8Array;
        data: Uint8Array;
    }): Promise<boolean>;
}
//# sourceMappingURL=ecdsa.d.ts.map