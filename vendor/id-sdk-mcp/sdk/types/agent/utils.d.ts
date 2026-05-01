import type { JsonWebKey, IDCrypto } from '../crypto/index.js';
import { RequireOnly } from '../common/index.js';
import { Readable } from 'readable-stream';
import { ReadableWebToNodeStream } from 'readable-web-to-node-stream';
import { ManagedKey, ManagedKeyPair, PortableKey, PortableKeyPair } from './types/managed-key.js';
export declare function blobToIsomorphicNodeReadable(blob: Blob): Readable;
export declare function cryptoToManagedKey(options: {
    cryptoKey: IDCrypto.CryptoKey;
    keyData: RequireOnly<ManagedKey, 'kms'>;
}): ManagedKey;
export declare function cryptoToManagedKeyPair(options: {
    cryptoKeyPair: IDCrypto.CryptoKeyPair;
    keyData: RequireOnly<ManagedKey, 'kms' | 'state'>;
}): ManagedKeyPair;
export declare function cryptoToPortableKey(options: {
    cryptoKey: IDCrypto.CryptoKey;
    keyData: RequireOnly<ManagedKey, 'kms'>;
}): PortableKey;
export declare function cryptoToPortableKeyPair(options: {
    cryptoKeyPair: IDCrypto.CryptoKeyPair;
    keyData: RequireOnly<ManagedKey, 'kms'>;
}): PortableKeyPair;
/**
 * Type guard function to check if the given key is a ManagedKey.
 *
 * @param key The key to check.
 * @returns True if the key is a ManagedKeyPair, false otherwise.
 */
export declare function isManagedKey(key: ManagedKey | ManagedKeyPair | undefined): key is ManagedKey;
/**
 * Type guard function to check if the given key is a ManagedKeyPair.
 *
 * @param key The key to check.
 * @returns True if the key is a ManagedKeyPair, false otherwise.
 */
export declare function isManagedKeyPair(key: ManagedKey | ManagedKeyPair | undefined): key is ManagedKeyPair;
export declare function managedKeyToJwk({ key }: {
    key: RequireOnly<ManagedKey, 'algorithm' | 'extractable' | 'material' | 'type' | 'usages'>;
}): Promise<JsonWebKey>;
export declare function managedToCryptoKey({ key }: {
    key: RequireOnly<ManagedKey, 'algorithm' | 'extractable' | 'material' | 'type' | 'usages'>;
}): IDCrypto.CryptoKey;
export declare function webReadableToIsomorphicNodeReadable(webReadable: ReadableStream<any>): ReadableWebToNodeStream;
//# sourceMappingURL=utils.d.ts.map