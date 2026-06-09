export type DidDhtMethod = 'did:dht' | 'did:key';

export interface DidDhtPublisher {
  /** Returns success=false on soft failures (gateway unreachable, timeout). Throws only on programming errors. */
  publish(): Promise<{ success: boolean; method: DidDhtMethod; reason?: string }>;
  /** Start background re-publish timer to keep the DID document alive in the DHT. Idempotent. */
  startAutoPublish(): void;
  stop(): void;
  readonly currentMethod: DidDhtMethod;
}
