// Copyright 2026 Abaxx Technologies
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

export type DidDhtMethod = 'did:dht' | 'did:key';

export interface DidDhtPublisher {
  /** Returns success=false on soft failures (gateway unreachable, timeout). Throws only on programming errors. */
  publish(): Promise<{ success: boolean; method: DidDhtMethod; reason?: string }>;
  /** Start background re-publish timer to keep the DID document alive in the DHT. Idempotent. */
  startAutoPublish(): void;
  stop(): void;
  readonly currentMethod: DidDhtMethod;
}
