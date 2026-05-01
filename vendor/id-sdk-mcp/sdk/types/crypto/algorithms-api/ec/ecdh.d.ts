import type { IDCrypto } from '../../types/iddwn-crypto.js';
import { BaseEllipticCurveAlgorithm } from './base.js';
export declare abstract class BaseEcdhAlgorithm extends BaseEllipticCurveAlgorithm {
    readonly name: string;
    keyUsages: IDCrypto.KeyPairUsage;
    checkAlgorithmOptions(options: {
        algorithm: IDCrypto.EcdhDeriveKeyOptions;
        baseKey: IDCrypto.CryptoKey;
    }): void;
    sign(): Promise<Uint8Array>;
    verify(): Promise<boolean>;
}
//# sourceMappingURL=ecdh.d.ts.map