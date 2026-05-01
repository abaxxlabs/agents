import type { IDCrypto } from '../types/iddwn-crypto.js';
import { BasePbkdf2Algorithm } from '../algorithms-api/index.js';
export declare class Pbkdf2Algorithm extends BasePbkdf2Algorithm {
    readonly hashAlgorithms: string[];
    deriveBits(options: {
        algorithm: IDCrypto.Pbkdf2Options;
        baseKey: IDCrypto.CryptoKey;
        length: number;
    }): Promise<Uint8Array>;
    importKey(options: {
        format: IDCrypto.KeyFormat;
        keyData: Uint8Array;
        algorithm: IDCrypto.Algorithm;
        extractable: boolean;
        keyUsages: IDCrypto.KeyUsage[];
    }): Promise<IDCrypto.CryptoKey>;
}
//# sourceMappingURL=pbkdf2.d.ts.map