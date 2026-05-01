import type { IDCrypto } from '../types/iddwn-crypto.js';
import { BaseEdDsaAlgorithm } from '../algorithms-api/index.js';
export declare class EdDsaAlgorithm extends BaseEdDsaAlgorithm {
    readonly namedCurves: string[];
    generateKey(options: {
        algorithm: IDCrypto.EdDsaGenerateKeyOptions;
        extractable: boolean;
        keyUsages: IDCrypto.KeyUsage[];
    }): Promise<IDCrypto.CryptoKeyPair>;
    sign(options: {
        algorithm: IDCrypto.EdDsaOptions;
        key: IDCrypto.CryptoKey;
        data: Uint8Array;
    }): Promise<Uint8Array>;
    verify(options: {
        algorithm: IDCrypto.EdDsaOptions;
        key: IDCrypto.CryptoKey;
        signature: Uint8Array;
        data: Uint8Array;
    }): Promise<boolean>;
}
//# sourceMappingURL=eddsa.d.ts.map