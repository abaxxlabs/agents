export declare class XChaCha20 {
    static decrypt(options: {
        data: Uint8Array;
        key: Uint8Array;
        nonce: Uint8Array;
    }): Promise<Uint8Array>;
    static encrypt(options: {
        data: Uint8Array;
        key: Uint8Array;
        nonce: Uint8Array;
    }): Promise<Uint8Array>;
    static generateKey(): Promise<Uint8Array>;
}
//# sourceMappingURL=xchacha20.d.ts.map