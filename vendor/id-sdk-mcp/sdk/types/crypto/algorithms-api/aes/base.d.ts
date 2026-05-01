import type { IDCrypto } from '../../types/iddwn-crypto.js';
import { CryptoAlgorithm } from '../crypto-algorithm.js';
export declare abstract class BaseAesAlgorithm extends CryptoAlgorithm {
    checkGenerateKey(options: {
        algorithm: IDCrypto.AesGenerateKeyOptions;
        keyUsages: IDCrypto.KeyUsage[];
    }): void;
    abstract generateKey(options: {
        algorithm: IDCrypto.AesGenerateKeyOptions;
        extractable: boolean;
        keyUsages: IDCrypto.KeyUsage[];
    }): Promise<IDCrypto.CryptoKey>;
    deriveBits(): Promise<Uint8Array>;
    sign(): Promise<Uint8Array>;
    verify(): Promise<boolean>;
}
//# sourceMappingURL=base.d.ts.map