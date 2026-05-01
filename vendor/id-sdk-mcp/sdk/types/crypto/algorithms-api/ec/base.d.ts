import type { IDCrypto } from '../../types/iddwn-crypto.js';
import { CryptoAlgorithm } from '../crypto-algorithm.js';
export declare abstract class BaseEllipticCurveAlgorithm extends CryptoAlgorithm {
    abstract namedCurves: string[];
    checkGenerateKey(options: {
        algorithm: IDCrypto.EcGenerateKeyOptions;
        keyUsages: IDCrypto.KeyUsage[];
    }): void;
    decrypt(): Promise<Uint8Array>;
    encrypt(): Promise<Uint8Array>;
    abstract generateKey(options: {
        algorithm: IDCrypto.EcGenerateKeyOptions;
        extractable: boolean;
        keyUsages: IDCrypto.KeyUsage[];
    }): Promise<IDCrypto.CryptoKeyPair>;
}
//# sourceMappingURL=base.d.ts.map