import type { IDCrypto } from '../../types/iddwn-crypto.js';
import { BaseEllipticCurveAlgorithm } from './base.js';
export declare abstract class BaseEdDsaAlgorithm extends BaseEllipticCurveAlgorithm {
    readonly name: string;
    readonly keyUsages: IDCrypto.KeyPairUsage;
    checkAlgorithmOptions(options: {
        algorithm: IDCrypto.EdDsaOptions;
    }): void;
    deriveBits(): Promise<Uint8Array>;
    abstract sign(options: {
        algorithm: IDCrypto.EdDsaOptions;
        key: IDCrypto.CryptoKey;
        data: Uint8Array;
    }): Promise<Uint8Array>;
    abstract verify(options: {
        algorithm: IDCrypto.EdDsaOptions;
        key: IDCrypto.CryptoKey;
        signature: Uint8Array;
        data: Uint8Array;
    }): Promise<boolean>;
}
//# sourceMappingURL=eddsa.d.ts.map