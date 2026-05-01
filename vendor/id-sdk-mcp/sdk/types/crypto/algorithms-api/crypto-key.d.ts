import type { IDCrypto } from '../types/iddwn-crypto.js';
export declare class CryptoKey implements IDCrypto.CryptoKey {
    algorithm: IDCrypto.KeyAlgorithm | IDCrypto.GenerateKeyOptions;
    extractable: boolean;
    material: Uint8Array;
    type: IDCrypto.KeyType;
    usages: IDCrypto.KeyUsage[];
    constructor(algorithm: IDCrypto.KeyAlgorithm | IDCrypto.GenerateKeyOptions, extractable: boolean, material: Uint8Array, type: IDCrypto.KeyType, usages: IDCrypto.KeyUsage[]);
}
//# sourceMappingURL=crypto-key.d.ts.map