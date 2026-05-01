type DeriveKeyOptions = {
    hash: 'SHA-256' | 'SHA-384' | 'SHA-512';
    password: Uint8Array;
    salt: Uint8Array;
    iterations: number;
    length: number;
};
export declare class Pbkdf2 {
    static deriveKey(options: DeriveKeyOptions): Promise<Uint8Array>;
    private static deriveKeyWithNodeCrypto;
    private static deriveKeyWithWebCrypto;
}
export {};
//# sourceMappingURL=pbkdf2.d.ts.map