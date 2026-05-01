import type { IDCrypto } from '../types/iddwn-crypto.js';
import { BaseEcdhAlgorithm } from '../algorithms-api/index.js';
export declare class EcdhAlgorithm extends BaseEcdhAlgorithm {
    readonly namedCurves: string[];
    deriveBits(options: {
        algorithm: IDCrypto.EcdhDeriveKeyOptions;
        baseKey: IDCrypto.CryptoKey;
        length: number | null;
    }): Promise<Uint8Array>;
    generateKey(options: {
        algorithm: IDCrypto.EcGenerateKeyOptions | IDCrypto.EcdsaGenerateKeyOptions;
        extractable: boolean;
        keyUsages: IDCrypto.KeyUsage[];
    }): Promise<IDCrypto.CryptoKeyPair>;
}
//# sourceMappingURL=ecdh.d.ts.map