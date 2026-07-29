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

export interface AgentRecord {
  did: string;
  name: string;
  ownerDid: string;
  createdAt: string; // ISO 8601
  /** AES-256-GCM wrapped Ed25519 private key (null/undefined if created before key persistence). */
  encryptedPrivateKey?: Buffer | null;
  /** Raw Ed25519 public key bytes (null/undefined if created before key persistence). */
  publicKey?: Buffer | null;
}

export interface AgentListFilter {
  ownerDid?: string;
  limit?: number; // default: 100, max: 100
}

/**
 * Server-internal agent registry. Authorization occurs before this interface.
 */
export interface AgentStore {
  /** Register a new agent. Throws on duplicate DID. */
  create(agent: Omit<AgentRecord, 'createdAt'>): Promise<AgentRecord>;

  findByDid(did: string): Promise<AgentRecord | null>;

  /** Lists at most 100 agents. */
  list(filter?: AgentListFilter): Promise<AgentRecord[]>;

  listAll(): Promise<AgentRecord[]>;

  count(filter?: { ownerDid?: string }): Promise<number>;
}
