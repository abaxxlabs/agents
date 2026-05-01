import type { IDCrypto } from '../types/iddwn-crypto.js';
import { BaseAesCtrAlgorithm } from '../algorithms-api/index.js';
export declare class AesCtrAlgorithm extends BaseAesCtrAlgorithm {
    decrypt(options: {
        algorithm: IDCrypto.AesCtrOptions;
        key: IDCrypto.CryptoKey;
        data: Uint8Array;
    }): Promise<Uint8Array>;
    encrypt(options: {
        algorithm: IDCrypto.AesCtrOptions;
        key: IDCrypto.CryptoKey;
        data: Uint8Array;
    }): Promise<Uint8Array>;
    generateKey(options: {
        algorithm: IDCrypto.AesGenerateKeyOptions;
        extractable: boolean;
        keyUsages: IDCrypto.KeyUsage[];
    }): Promise<IDCrypto.CryptoKey>;
}
//# sourceMappingURL=aes-ctr.d.ts.map