import type { IDCrypto } from '../types/iddwn-crypto.js';
import { BaseEcdsaAlgorithm } from '../algorithms-api/index.js';
export declare class EcdsaAlgorithm extends BaseEcdsaAlgorithm {
    readonly hashAlgorithms: string[];
    readonly namedCurves: string[];
    generateKey(options: {
        algorithm: IDCrypto.EcdsaGenerateKeyOptions;
        extractable: boolean;
        keyUsages: IDCrypto.KeyUsage[];
    }): Promise<IDCrypto.CryptoKeyPair>;
    sign(options: {
        algorithm: IDCrypto.EcdsaOptions;
        key: IDCrypto.CryptoKey;
        data: Uint8Array;
    }): Promise<Uint8Array>;
    verify(options: {
        algorithm: IDCrypto.EcdsaOptions;
        key: IDCrypto.CryptoKey;
        signature: Uint8Array;
        data: Uint8Array;
    }): Promise<boolean>;
}
//# sourceMappingURL=ecdsa.d.ts.map