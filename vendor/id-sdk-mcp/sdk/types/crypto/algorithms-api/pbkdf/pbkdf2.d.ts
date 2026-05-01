import type { IDCrypto } from '../../types/iddwn-crypto.js';
import { CryptoAlgorithm } from '../crypto-algorithm.js';
export declare abstract class BasePbkdf2Algorithm extends CryptoAlgorithm {
    readonly name: string;
    abstract readonly hashAlgorithms: string[];
    readonly keyUsages: IDCrypto.KeyUsage[];
    checkAlgorithmOptions(options: {
        algorithm: IDCrypto.Pbkdf2Options;
        baseKey: IDCrypto.CryptoKey;
    }): void;
    checkImportKey(options: {
        algorithm: IDCrypto.Algorithm;
        format: IDCrypto.KeyFormat;
        extractable: boolean;
        keyUsages: IDCrypto.KeyUsage[];
    }): void;
    decrypt(): Promise<Uint8Array>;
    encrypt(): Promise<Uint8Array>;
    generateKey(): Promise<IDCrypto.CryptoKey>;
    sign(): Promise<Uint8Array>;
    verify(): Promise<boolean>;
}
//# sourceMappingURL=pbkdf2.d.ts.map