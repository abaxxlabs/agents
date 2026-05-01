import type { IDCrypto } from '../../types/iddwn-crypto.js';
import { BaseAesAlgorithm } from './base.js';
export declare abstract class BaseAesCtrAlgorithm extends BaseAesAlgorithm {
    readonly name = "AES-CTR";
    readonly keyUsages: IDCrypto.KeyUsage[];
    checkAlgorithmOptions(options: {
        algorithm: IDCrypto.AesCtrOptions;
        key: IDCrypto.CryptoKey;
    }): void;
}
//# sourceMappingURL=ctr.d.ts.map